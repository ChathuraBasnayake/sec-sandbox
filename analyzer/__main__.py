"""Entry point for the AI Threat Analyst service."""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from .consumer import consume_detonations
from .models import ThreatVerdict, RiskLevel, Severity
from .rules import analyze as rule_analyze, needs_llm_analysis

# Load environment variables from .env file
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# ─── ANSI Colors ─────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
MAGENTA = "\033[35m"
CYAN    = "\033[36m"
WHITE   = "\033[37m"
BG_RED  = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"


def print_banner():
    print(f"""
  {CYAN}{BOLD}╔══════════════════════════════════════════════════════════════╗
  ║         🧠  AI THREAT ANALYST  — NPM Detonator            ║
  ║                Powered by OpenRouter LLM                   ║
  ╚══════════════════════════════════════════════════════════════╝{RESET}
""")


def risk_badge(level: RiskLevel) -> str:
    """Return a colored badge for the risk level."""
    if level == RiskLevel.MALICIOUS:
        return f"{BG_RED}{WHITE}{BOLD} 🔴 MALICIOUS {RESET}"
    elif level == RiskLevel.SUSPICIOUS:
        return f"{BG_YELLOW}{BOLD} 🟡 SUSPICIOUS {RESET}"
    else:
        return f"{BG_GREEN}{BOLD} 🟢 SAFE {RESET}"


def severity_color(severity: Severity) -> str:
    """Return ANSI color for a severity level."""
    return {
        Severity.CRITICAL: RED + BOLD,
        Severity.HIGH: RED,
        Severity.MEDIUM: YELLOW,
        Severity.LOW: BLUE,
        Severity.INFO: DIM,
    }.get(severity, DIM)


def threat_bar(score: int) -> str:
    """Render a visual threat score bar."""
    width = 30
    filled = int(score / 100 * width)
    empty = width - filled

    if score >= 60:
        color = RED
    elif score >= 25:
        color = YELLOW
    else:
        color = GREEN

    bar = f"{color}{'█' * filled}{DIM}{'░' * empty}{RESET}"
    return f"[{bar}] {color}{BOLD}{score}/100{RESET}"


def print_verdict(verdict: ThreatVerdict):
    """Print a beautifully formatted threat verdict."""
    badge = risk_badge(verdict.risk_level)
    bar = threat_bar(verdict.threat_score)

    print(f"  {BOLD}{'━' * 60}{RESET}")
    print()
    print(f"  {BOLD}Package:{RESET}       {WHITE}{BOLD}{verdict.package_name}{RESET}")
    print(f"  {BOLD}Detonation:{RESET}    {DIM}{verdict.detonation_id}{RESET}")
    print(f"  {BOLD}Method:{RESET}        {DIM}{verdict.analysis_method}{RESET}")
    print(f"  {BOLD}Events:{RESET}        {verdict.events_analyzed} total ({verdict.execve_count} EXECVE, {verdict.openat_count} OPENAT, {verdict.connect_count} CONNECT, {verdict.write_count} WRITE, {verdict.unlink_count} UNLINK)")
    print()
    print(f"  {BOLD}Threat Score:{RESET}  {bar}")
    print(f"  {BOLD}Risk Level:{RESET}    {badge}")
    print()

    if verdict.findings:
        print(f"  {BOLD}Findings ({len(verdict.findings)}):{RESET}")
        print(f"  {DIM}{'─' * 56}{RESET}")
        for i, finding in enumerate(verdict.findings, 1):
            color = severity_color(finding.severity)
            mitre_tag = f" {DIM}[{finding.mitre_id}]{RESET}" if finding.mitre_id else ""
            print(f"    {color}[{finding.severity.value}]{RESET}{mitre_tag} {finding.description}")
            if finding.mitre_id and finding.mitre_name:
                print(f"           {DIM}MITRE: {finding.mitre_id} — {finding.mitre_name}{RESET}")
            print(f"           {DIM}Category: {finding.category.value}{RESET}")
            print(f"           {DIM}Evidence: {finding.evidence}{RESET}")
            if i < len(verdict.findings):
                print()
        print(f"  {DIM}{'─' * 56}{RESET}")
    else:
        print(f"  {BOLD}Findings:{RESET}      {GREEN}No suspicious behavior detected{RESET}")

    # Attack chain narrative (from Gemini)
    if verdict.executive_summary:
        print()
        print(f"  {MAGENTA}{BOLD}🔍 EXECUTIVE SUMMARY (Gemini):{RESET}")
        print(f"    {verdict.executive_summary}")
    
    if verdict.attack_chain:
        print()
        print(f"  {RED}{BOLD}⚔️  ATTACK CHAIN:{RESET}")
        for stage in verdict.attack_chain:
            print(f"    {YELLOW}→{RESET} {stage}")

    print()
    print(f"  {BOLD}Recommendation:{RESET}")
    print(f"    {verdict.recommendation}")
    print()
    print(f"  {BOLD}{'━' * 60}{RESET}")
    print()


def save_report(verdict: ThreatVerdict):
    """Save the verdict as a JSON report to reports/ directory."""
    reports_dir = Path(__file__).parent.parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    # Sanitize the filename (scoped packages like @nestjs/core contain forward slashes)
    safe_id = verdict.detonation_id.replace("/", "_")
    filename = f"{safe_id}.json"
    filepath = reports_dir / filename
    
    report_data = verdict.model_dump(mode="json")
    
    with open(filepath, "w") as f:
        json.dump(report_data, f, indent=2, default=str)
    
    print(f"  {DIM}📄 Report saved: reports/{filename}{RESET}")


def main():
    """Main entry point — consume from Kafka and analyze each detonation."""
    
    # Check for standalone static scan mode
    if len(sys.argv) > 1 and sys.argv[1] == "--scan":
        return run_static_scan()
    
    broker = os.getenv("KAFKA_BROKER", "localhost:9092")
    topic = os.getenv("KAFKA_TOPIC", "syscall-telemetry")
    
    llm_model = os.getenv("LLM_MODEL", "minimax/minimax-m2.5")
    
    print_banner()
    
    print(f"  {BOLD}Configuration:{RESET}")
    print(f"    Kafka Broker:  {broker}")
    print(f"    Kafka Topic:   {topic}")
    print(f"    LLM Provider:  OpenRouter ({llm_model})")
    print(f"    Scoring Mode:  Hybrid (metadata → rules → LLM → attack chain)")
    print()
    
    for pkg_name, det_id, events in consume_detonations(broker, topic):
        print(f"\n  {CYAN}{BOLD}📦 Detonation received:{RESET} {WHITE}{BOLD}{pkg_name}{RESET} ({len(events)} events)")
        print(f"     {DIM}Detonation ID: {det_id}{RESET}")
        
        # Step 1: npm registry metadata check
        print(f"     {DIM}[1/4] Querying npm registry...{RESET}", end="", flush=True)
        try:
            from .npm_metadata import analyze_metadata
            meta_findings, meta_summary = analyze_metadata(pkg_name)
            if meta_summary.get("available"):
                downloads = meta_summary.get("weekly_downloads", "?")
                age = meta_summary.get("age_days", "?")
                print(f" {len(meta_findings)} signals (downloads={downloads}/wk, age={age}d)")
            elif meta_summary.get("error"):
                print(f" {DIM}not on npm ({meta_summary['error']}){RESET}")
            else:
                print(f" done")
        except Exception as e:
            meta_findings = []
            meta_summary = {}
            print(f" {RED}failed: {e}{RESET}")
        
        # Step 2: Rule-based analysis
        print(f"     {DIM}[2/4] Running rule engine...{RESET}", end="", flush=True)
        verdict = rule_analyze(events, pkg_name, det_id)
        
        # Merge metadata findings into verdict
        if meta_findings:
            verdict.findings.extend(meta_findings)
            # Add metadata score (capped contribution)
            meta_score = sum(5 for f in meta_findings if f.severity in (Severity.HIGH, Severity.CRITICAL))
            meta_score += sum(2 for f in meta_findings if f.severity == Severity.MEDIUM)
            verdict.threat_score = min(100, verdict.threat_score + meta_score)
        
        print(f" score={verdict.threat_score} ({verdict.risk_level.value})")
        
        # Step 3: LLM analysis (only if ambiguous)
        if needs_llm_analysis(verdict):
            print(f"     {DIM}[3/4] Score ambiguous ({verdict.threat_score}) — consulting LLM...{RESET}", end="", flush=True)
            try:
                from .llm import analyze_with_llm
                verdict = analyze_with_llm(events, verdict)
                print(f" refined to {verdict.threat_score} ({verdict.risk_level.value})")
            except Exception as e:
                print(f" {RED}failed: {e}{RESET}")
                verdict.analysis_method = f"rules only (LLM error: {e})"
        else:
            reason = "clearly safe" if verdict.threat_score <= 10 else "clearly malicious"
            print(f"     {DIM}[3/4] LLM scoring skipped — {reason}{RESET}")
        
        # Step 4: Attack chain narrative (malicious packages only)
        if verdict.threat_score >= 60:
            print(f"     {DIM}[4/4] Generating attack chain narrative...{RESET}", end="", flush=True)
            try:
                from .llm import generate_attack_chain
                verdict = generate_attack_chain(events, verdict)
                stages = len(verdict.attack_chain)
                print(f" {stages} stages identified")
            except Exception as e:
                print(f" {RED}failed: {e}{RESET}")
        else:
            print(f"     {DIM}[4/4] Attack chain skipped — not malicious{RESET}")
        
        print()
        print_verdict(verdict)
        save_report(verdict)


def run_static_scan():
    """Run standalone static scan on a local package."""
    if len(sys.argv) < 3:
        print(f"  {RED}Usage: python3 -m analyzer --scan <path-to-package-or-tarball>{RESET}")
        sys.exit(1)
    
    target = sys.argv[2]
    
    print_banner()
    print(f"  {BOLD}Static Source Code Scan{RESET}")
    print(f"  {DIM}{'━' * 56}{RESET}")
    print(f"  Target: {WHITE}{BOLD}{target}{RESET}")
    print()
    
    from .static_scan import scan_package
    findings = scan_package(target)
    
    if not findings:
        print(f"  {GREEN}{BOLD}✅ No suspicious patterns detected{RESET}")
        print()
        return
    
    print(f"  {RED}{BOLD}⚠ Found {len(findings)} suspicious pattern(s):{RESET}")
    print(f"  {DIM}{'─' * 56}{RESET}")
    
    for i, finding in enumerate(findings, 1):
        color = severity_color(finding.severity)
        mitre_tag = f" {DIM}[{finding.mitre_id}]{RESET}" if finding.mitre_id else ""
        print(f"    {color}[{finding.severity.value}]{RESET}{mitre_tag} {finding.description}")
        print(f"           {DIM}Evidence: {finding.evidence}{RESET}")
        if i < len(findings):
            print()
    
    print(f"  {DIM}{'─' * 56}{RESET}")
    print()
    
    # Compute a static-only risk score
    score = 0
    for f in findings:
        if f.severity == Severity.CRITICAL:
            score += 25
        elif f.severity == Severity.HIGH:
            score += 15
        elif f.severity == Severity.MEDIUM:
            score += 5
        else:
            score += 2
    score = min(100, score)
    
    bar = threat_bar(score)
    print(f"  {BOLD}Static Risk Score:{RESET}  {bar}")
    print()


if __name__ == "__main__":
    main()
