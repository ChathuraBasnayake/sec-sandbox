"""Gemini LLM integration for nuanced threat analysis.

Used only for ambiguous cases (rule score 11-59) where deterministic
rules can't make a clear SAFE/MALICIOUS call.
"""

import json
import os
from datetime import datetime

import google.generativeai as genai

from .models import (
    ThreatVerdict, Finding, SyscallEvent,
    Severity, Category, RiskLevel,
)


def configure():
    """Configure the Gemini SDK with the API key from environment."""
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key or api_key == "your-gemini-api-key-here":
        raise ValueError(
            "GEMINI_API_KEY not set. Copy analyzer/.env.example to analyzer/.env "
            "and add your API key from https://aistudio.google.com/apikey"
        )
    genai.configure(api_key=api_key)


def build_prompt(events: list[SyscallEvent], rule_verdict: ThreatVerdict) -> str:
    """Build a structured analysis prompt from syscall events."""
    
    # Summarize execve events
    exec_events = [e for e in events if e.event_type == "EXECVE"]
    open_events = [e for e in events if e.event_type == "OPENAT"]
    
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
    
    # Build the rule findings summary
    rule_findings = ""
    if rule_verdict.findings:
        rule_findings = "\n".join(
            f"  - [{f.severity}] {f.description}: {f.evidence}"
            for f in rule_verdict.findings
        )
    else:
        rule_findings = "  (no findings from rule engine)"
    
    prompt = f"""You are a cybersecurity analyst specializing in npm supply chain attacks.

Analyze the following syscall telemetry captured during an npm package installation in an isolated sandbox container.

## Package Information
- **Package:** {rule_verdict.package_name}
- **Detonation ID:** {rule_verdict.detonation_id}
- **Total Events:** {len(events)} ({rule_verdict.execve_count} EXECVE, {rule_verdict.openat_count} OPENAT)

## Rule Engine Pre-Score
The automated rule engine scored this package at **{rule_verdict.threat_score}/100**.
Findings:
{rule_findings}

## Processes Spawned ({len(exec_events)} total)
{chr(10).join(process_list[:30]) if process_list else "  (none beyond standard npm/node)"}

## Suspicious File Access ({len(suspicious_files)} unique files)
{chr(10).join(suspicious_files[:50]) if suspicious_files else "  (none beyond standard npm paths)"}

## Your Task
Based on this syscall behavior, provide a threat assessment. Consider:
1. Are the file accesses consistent with a normal npm install, or do they indicate malicious intent?
2. Are any of the spawned processes unusual for an npm package installation?
3. Could any of the behavior be legitimate (e.g., native module compilation, config file reading)?

Respond with ONLY a JSON object in this exact format (no markdown, no explanation):
{{
  "threat_score": <int 0-100>,
  "risk_level": "<SAFE|SUSPICIOUS|MALICIOUS>",
  "findings": [
    {{
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "category": "<credential_theft|data_exfiltration|reverse_shell|recon|persistence|suspicious_activity>",
      "description": "<what was detected>",
      "evidence": "<specific syscall evidence>"
    }}
  ],
  "recommendation": "<one-line recommendation>"
}}"""
    
    return prompt


def analyze_with_llm(
    events: list[SyscallEvent],
    rule_verdict: ThreatVerdict,
) -> ThreatVerdict:
    """Send events to Gemini for nuanced threat analysis."""
    
    configure()
    
    prompt = build_prompt(events, rule_verdict)
    
    model = genai.GenerativeModel(
        "gemini-2.0-flash",
        generation_config=genai.GenerationConfig(
            response_mime_type="application/json",
            temperature=0.1,  # Low temperature for consistent analysis
        ),
    )
    
    response = model.generate_content(prompt)
    
    # Parse the JSON response
    try:
        result = json.loads(response.text)
    except json.JSONDecodeError:
        # If the LLM doesn't return valid JSON, fall back to rule verdict
        rule_verdict.analysis_method = "rules (LLM parse failed)"
        return rule_verdict
    
    # Build findings from LLM response
    findings = []
    for f in result.get("findings", []):
        try:
            findings.append(Finding(
                severity=Severity(f.get("severity", "MEDIUM")),
                category=Category(f.get("category", "suspicious_activity")),
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
            ))
        except (ValueError, KeyError):
            continue
    
    # Build the LLM-enhanced verdict
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
        analysis_method="hybrid (rules + Gemini)",
        events_analyzed=len(events),
        execve_count=rule_verdict.execve_count,
        openat_count=rule_verdict.openat_count,
    )
