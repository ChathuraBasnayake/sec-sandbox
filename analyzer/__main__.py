"""Entry point for the AI Threat Analyst service."""

import json
import os
import sys

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
  ║                    Powered by Gemini                       ║
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
    print(f"  {BOLD}Events:{RESET}        {verdict.events_analyzed} total ({verdict.execve_count} EXECVE, {verdict.openat_count} OPENAT)")
    print()
    print(f"  {BOLD}Threat Score:{RESET}  {bar}")
    print(f"  {BOLD}Risk Level:{RESET}    {badge}")
    print()

    if verdict.findings:
        print(f"  {BOLD}Findings ({len(verdict.findings)}):{RESET}")
        print(f"  {DIM}{'─' * 56}{RESET}")
        for i, finding in enumerate(verdict.findings, 1):
            color = severity_color(finding.severity)
            print(f"    {color}[{finding.severity.value}]{RESET} {finding.description}")
            print(f"           {DIM}Category: {finding.category.value}{RESET}")
            print(f"           {DIM}Evidence: {finding.evidence}{RESET}")
            if i < len(verdict.findings):
                print()
        print(f"  {DIM}{'─' * 56}{RESET}")
    else:
        print(f"  {BOLD}Findings:{RESET}      {GREEN}No suspicious behavior detected{RESET}")

    print()
    print(f"  {BOLD}Recommendation:{RESET}")
    print(f"    {verdict.recommendation}")
    print()
    print(f"  {BOLD}{'━' * 60}{RESET}")
    print()


def main():
    """Main entry point — consume from Kafka and analyze each detonation."""
    
    broker = os.getenv("KAFKA_BROKER", "localhost:9092")
    topic = os.getenv("KAFKA_TOPIC", "syscall-telemetry")
    
    print_banner()
    
    print(f"  {BOLD}Configuration:{RESET}")
    print(f"    Kafka Broker:  {broker}")
    print(f"    Kafka Topic:   {topic}")
    print(f"    LLM Provider:  Gemini (gemini-2.0-flash)")
    print(f"    Scoring Mode:  Hybrid (rules → LLM for ambiguous)")
    print()
    
    for pkg_name, det_id, events in consume_detonations(broker, topic):
        print(f"\n  {CYAN}{BOLD}📦 Detonation received:{RESET} {WHITE}{BOLD}{pkg_name}{RESET} ({len(events)} events)")
        print(f"     {DIM}Detonation ID: {det_id}{RESET}")
        
        # Step 1: Rule-based analysis
        print(f"     {DIM}[1/2] Running rule engine...{RESET}", end="", flush=True)
        verdict = rule_analyze(events, pkg_name, det_id)
        print(f" score={verdict.threat_score} ({verdict.risk_level.value})")
        
        # Step 2: LLM analysis (only if ambiguous)
        if needs_llm_analysis(verdict):
            print(f"     {DIM}[2/2] Score ambiguous ({verdict.threat_score}) — consulting Gemini...{RESET}", end="", flush=True)
            try:
                from .llm import analyze_with_llm
                verdict = analyze_with_llm(events, verdict)
                print(f" refined to {verdict.threat_score} ({verdict.risk_level.value})")
            except Exception as e:
                print(f" {RED}failed: {e}{RESET}")
                verdict.analysis_method = f"rules only (LLM error: {e})"
        else:
            reason = "clearly safe" if verdict.threat_score <= 10 else "clearly malicious"
            print(f"     {DIM}[2/2] LLM skipped — {reason}{RESET}")
        
        print()
        print_verdict(verdict)


if __name__ == "__main__":
    main()
