"""LLM integration via OpenRouter (OpenAI-compatible API).

Uses MiniMax M2.5 (free) by default via OpenRouter.
Two modes:
1. Ambiguous analysis: Full verdict refinement for scores 11-59.
2. Attack chain narrative: Executive summary + staged attack reconstruction
   for confirmed malicious packages (score >= 60).
"""

import json
import os
from datetime import datetime

from openai import OpenAI

from .models import (
    ThreatVerdict, Finding, SyscallEvent,
    Severity, Category, RiskLevel,
)


def get_client() -> tuple[OpenAI, str]:
    """Get OpenRouter client and model name."""
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key or api_key == "your-openrouter-api-key-here":
        raise ValueError(
            "OPENROUTER_API_KEY not set. Get a free key from https://openrouter.ai/keys "
            "and add it to analyzer/.env"
        )
    
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )
    
    model = os.getenv("LLM_MODEL", "minimax/minimax-m2.5")
    return client, model


def _summarize_events(events: list[SyscallEvent], rule_verdict: ThreatVerdict) -> dict:
    """Build structured event summaries for LLM prompts."""
    exec_events = [e for e in events if e.event_type == "EXECVE"]
    open_events = [e for e in events if e.event_type == "OPENAT"]
    connect_events = [e for e in events if e.event_type == "CONNECT"]
    write_events = [e for e in events if e.event_type == "WRITE"]
    unlink_events = [e for e in events if e.event_type == "UNLINK"]
    
    # Deduplicate process spawns
    process_list = []
    seen_procs = set()
    for e in exec_events:
        key = f"{e.process_name}→{e.filename}"
        if key not in seen_procs:
            seen_procs.add(key)
            process_list.append(f"  - {e.process_name} executed: {e.filename} (PID={e.pid})")
    
    # Collect suspicious file accesses (skip normal npm paths)
    safe_prefixes = (
        "/usr/local/lib/node_modules/",
        "/usr/local/bin/",
        "/app/node_modules/",
        "/app/package",
        "/root/.npm/",
        "/tmp/npm-",
    )
    suspicious_files = []
    seen_files = set()
    for e in open_events:
        if any(e.filename.startswith(p) for p in safe_prefixes):
            continue
        if e.filename not in seen_files:
            seen_files.add(e.filename)
            suspicious_files.append(f"  - {e.process_name} accessed: {e.filename}")
    
    # Outbound connections
    connect_list = []
    for e in connect_events:
        ip_int = e.connect_ip
        ip_str = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
        connect_list.append(f"  - {e.process_name} → {ip_str}:{e.connect_port}")
    
    # File deletions
    unlink_list = [f"  - {e.process_name} deleted: {e.filename}" for e in unlink_events if e.filename]
    
    # Rule findings summary
    rule_findings = "\n".join(
        f"  - [{f.severity.value}] [{f.mitre_id}] {f.description}: {f.evidence}"
        for f in rule_verdict.findings
    ) if rule_verdict.findings else "  (no findings from rule engine)"
    
    return {
        "process_list": process_list,
        "suspicious_files": suspicious_files,
        "connect_list": connect_list,
        "unlink_list": unlink_list,
        "rule_findings": rule_findings,
        "exec_events": exec_events,
        "write_count": len(write_events),
    }


def build_prompt(events: list[SyscallEvent], rule_verdict: ThreatVerdict) -> str:
    """Build a structured analysis prompt for ambiguous verdicts."""
    s = _summarize_events(events, rule_verdict)
    
    prompt = f"""You are a cybersecurity analyst specializing in npm supply chain attacks.

Analyze the following syscall telemetry captured during an npm package installation in an isolated sandbox container.

## Package Information
- **Package:** {rule_verdict.package_name}
- **Detonation ID:** {rule_verdict.detonation_id}
- **Total Events:** {len(events)} ({rule_verdict.execve_count} EXECVE, {rule_verdict.openat_count} OPENAT, {rule_verdict.connect_count} CONNECT, {rule_verdict.write_count} WRITE, {rule_verdict.unlink_count} UNLINK)

## Rule Engine Pre-Score
The automated rule engine scored this package at **{rule_verdict.threat_score}/100**.
Findings:
{s['rule_findings']}

## Processes Spawned ({len(s['exec_events'])} total)
{chr(10).join(s['process_list'][:30]) if s['process_list'] else "  (none beyond standard npm/node)"}

## Suspicious File Access ({len(s['suspicious_files'])} unique files)
{chr(10).join(s['suspicious_files'][:50]) if s['suspicious_files'] else "  (none beyond standard npm paths)"}

## Outbound Connections
{chr(10).join(s['connect_list']) if s['connect_list'] else "  (none)"}

## File Deletions
{chr(10).join(s['unlink_list']) if s['unlink_list'] else "  (none)"}

## Your Task
Based on this syscall behavior, provide a threat assessment. Respond with ONLY a JSON object:
{{
  "threat_score": <int 0-100>,
  "risk_level": "<SAFE|SUSPICIOUS|MALICIOUS>",
  "findings": [
    {{
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "category": "<credential_theft|data_exfiltration|reverse_shell|recon|persistence|network|anti_forensics|suspicious_activity>",
      "description": "<what was detected>",
      "evidence": "<specific syscall evidence>",
      "mitre_id": "<MITRE ATT&CK technique ID>"
    }}
  ],
  "recommendation": "<one-line recommendation>"
}}"""
    
    return prompt


def build_attack_chain_prompt(events: list[SyscallEvent], rule_verdict: ThreatVerdict) -> str:
    """Build a prompt for attack chain narrative generation (malicious packages only)."""
    s = _summarize_events(events, rule_verdict)
    
    prompt = f"""You are a senior threat intelligence analyst. Analyze the following CONFIRMED MALICIOUS npm package and produce a structured attack chain analysis.

## Package: {rule_verdict.package_name}
## Threat Score: {rule_verdict.threat_score}/100 (MALICIOUS)

## Rule Engine Findings:
{s['rule_findings']}

## Processes Spawned:
{chr(10).join(s['process_list'][:30]) if s['process_list'] else "  (none)"}

## Suspicious File Access:
{chr(10).join(s['suspicious_files'][:50]) if s['suspicious_files'] else "  (none)"}

## Outbound Connections:
{chr(10).join(s['connect_list']) if s['connect_list'] else "  (none)"}

## File Deletions:
{chr(10).join(s['unlink_list']) if s['unlink_list'] else "  (none)"}

## Write Activity: {s['write_count']} write() syscalls

Respond with ONLY a JSON object:
{{
  "executive_summary": "<2-3 sentence summary of the attack for a security executive. Be specific about what data was targeted and what the attacker's likely goal was.>",
  "attack_chain": [
    "Stage 1 — <Phase Name>: <Description of what happens in this stage>",
    "Stage 2 — <Phase Name>: <Description>",
    "Stage 3 — <Phase Name>: <Description>"
  ]
}}

Guidelines:
- Use MITRE ATT&CK terminology where appropriate
- Be specific — reference actual files, commands, and IPs from the evidence
- Attack chain should be 2-5 stages, ordered chronologically
- Executive summary should be understandable by a non-technical security manager"""
    
    return prompt


def _call_llm(prompt: str) -> dict:
    """Call OpenRouter and return parsed JSON response."""
    client, model = get_client()
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a cybersecurity threat analyst. Always respond with valid JSON only, no markdown formatting."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
        max_tokens=2000,
    )
    
    text = response.choices[0].message.content.strip()
    
    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])
    
    return json.loads(text)


def analyze_with_llm(
    events: list[SyscallEvent],
    rule_verdict: ThreatVerdict,
) -> ThreatVerdict:
    """Send events to LLM for nuanced threat analysis (ambiguous scores)."""
    
    prompt = build_prompt(events, rule_verdict)
    result = _call_llm(prompt)
    
    # Build findings from LLM response
    findings = []
    for f in result.get("findings", []):
        try:
            findings.append(Finding(
                severity=Severity(f.get("severity", "MEDIUM")),
                category=Category(f.get("category", "suspicious_activity")),
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                mitre_id=f.get("mitre_id", ""),
                mitre_name="",
            ))
        except (ValueError, KeyError):
            continue
    
    score = max(0, min(100, result.get("threat_score", rule_verdict.threat_score)))
    
    risk_str = result.get("risk_level", "SUSPICIOUS").upper()
    try:
        risk_level = RiskLevel(risk_str)
    except ValueError:
        risk_level = RiskLevel.SUSPICIOUS
    
    return ThreatVerdict(
        package_name=rule_verdict.package_name,
        detonation_id=rule_verdict.detonation_id,
        threat_score=score,
        risk_level=risk_level,
        findings=findings,
        recommendation=result.get("recommendation", rule_verdict.recommendation),
        analyzed_at=datetime.now(),
        analysis_method="hybrid (rules + LLM)",
        events_analyzed=len(events),
        execve_count=rule_verdict.execve_count,
        openat_count=rule_verdict.openat_count,
        connect_count=rule_verdict.connect_count,
        write_count=rule_verdict.write_count,
        unlink_count=rule_verdict.unlink_count,
    )


def generate_attack_chain(
    events: list[SyscallEvent],
    verdict: ThreatVerdict,
) -> ThreatVerdict:
    """Generate an attack chain narrative for confirmed malicious packages.
    
    Enriches the existing verdict with executive_summary and attack_chain
    fields. Does NOT replace the findings or score.
    """
    prompt = build_attack_chain_prompt(events, verdict)
    result = _call_llm(prompt)
    
    verdict.executive_summary = result.get("executive_summary", "")
    verdict.attack_chain = result.get("attack_chain", [])
    verdict.analysis_method = "hybrid (rules + LLM attack chain)"
    
    return verdict
