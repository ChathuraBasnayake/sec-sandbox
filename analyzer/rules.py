"""Rule-based threat scoring engine.

Fast, deterministic scoring of syscall events using weighted indicators.
Skips the LLM for obvious SAFE (≤10) and MALICIOUS (≥60) verdicts.
"""

from .models import (
    SyscallEvent, ThreatVerdict, Finding,
    Severity, Category, RiskLevel,
)

# ──────────────────────────────────────────────────────────────
# Threat indicator rules: (pattern, points, severity, category, description)
# ──────────────────────────────────────────────────────────────

FILE_READ_RULES = [
    # CRITICAL — credential theft
    ("/etc/shadow",          30, Severity.CRITICAL, Category.CREDENTIAL_THEFT,    "Read /etc/shadow (password hashes)"),
    ("/.ssh/id_rsa",         25, Severity.CRITICAL, Category.CREDENTIAL_THEFT,    "Read SSH private key"),
    ("/.ssh/id_ed25519",     25, Severity.CRITICAL, Category.CREDENTIAL_THEFT,    "Read SSH private key (ed25519)"),
    ("/.ssh/authorized_keys",20, Severity.HIGH,     Category.CREDENTIAL_THEFT,    "Read SSH authorized_keys"),
    # HIGH — sensitive data
    ("/proc/self/environ",   15, Severity.HIGH,     Category.RECON,               "Read process environment variables (may contain secrets)"),
    ("/.bash_history",       15, Severity.HIGH,     Category.CREDENTIAL_THEFT,    "Read shell command history"),
    ("/.npmrc",              10, Severity.MEDIUM,   Category.CREDENTIAL_THEFT,    "Read .npmrc (may contain auth tokens)"),
    ("/.gitconfig",          10, Severity.MEDIUM,   Category.CREDENTIAL_THEFT,    "Read git configuration"),
    # HIGH — persistence
    ("/etc/crontab",         25, Severity.HIGH,     Category.PERSISTENCE,         "Accessed /etc/crontab (persistence mechanism)"),
    ("/etc/passwd",           5, Severity.LOW,      Category.RECON,               "Read /etc/passwd (user enumeration)"),
]

EXEC_RULES = [
    # HIGH — shell commands used by attackers
    ("curl",    20, Severity.HIGH,   Category.DATA_EXFILTRATION, "Executed curl (potential data exfiltration)"),
    ("wget",    20, Severity.HIGH,   Category.DATA_EXFILTRATION, "Executed wget (potential payload download)"),
    ("whoami",  10, Severity.MEDIUM, Category.RECON,             "Executed whoami (reconnaissance)"),
    ("id",      10, Severity.MEDIUM, Category.RECON,             "Executed id (privilege reconnaissance)"),
    ("uname",    5, Severity.LOW,    Category.RECON,             "Executed uname (system reconnaissance)"),
    ("chmod",   10, Severity.MEDIUM, Category.PERSISTENCE,       "Executed chmod (changed file permissions)"),
    ("chown",   10, Severity.MEDIUM, Category.PERSISTENCE,       "Executed chown (changed file ownership)"),
    # CRITICAL — reverse shell indicators
    ("nc",      25, Severity.CRITICAL, Category.REVERSE_SHELL,   "Executed netcat (potential reverse shell)"),
    ("ncat",    25, Severity.CRITICAL, Category.REVERSE_SHELL,   "Executed ncat (potential reverse shell)"),
    ("socat",   25, Severity.CRITICAL, Category.REVERSE_SHELL,   "Executed socat (potential reverse shell)"),
    ("python",  15, Severity.MEDIUM,   Category.SUSPICIOUS_ACTIVITY, "Spawned Python interpreter"),
    ("perl",    15, Severity.MEDIUM,   Category.SUSPICIOUS_ACTIVITY, "Spawned Perl interpreter"),
    ("ruby",    15, Severity.MEDIUM,   Category.SUSPICIOUS_ACTIVITY, "Spawned Ruby interpreter"),
]

# Processes that are expected during normal npm install
SAFE_PROCESSES = {"sh", "npm", "node", "mkdir", "cp", "sleep", "true", "DT_INIT"}
SAFE_FILE_PREFIXES = (
    "/usr/local/lib/node_modules/",
    "/usr/local/bin/",
    "/app/node_modules/",
    "/app/package",
    "/root/.npm/",
    "/tmp/npm-",
    "/proc/self/maps",
)


def analyze(events: list[SyscallEvent], package_name: str, detonation_id: str) -> ThreatVerdict:
    """Run rule-based analysis on a batch of syscall events.
    
    Returns a ThreatVerdict. If threat_score is between 11-59,
    the caller should escalate to LLM analysis for a refined verdict.
    """
    score = 0
    findings: list[Finding] = []
    seen_findings: set[str] = set()  # Deduplicate findings
    
    execve_count = 0
    openat_count = 0
    suspicious_execs: set[str] = set()
    
    for event in events:
        if event.event_type == "EXECVE":
            execve_count += 1
            proc_name = event.process_name.strip()
            filename = event.filename.strip()
            
            # Check exec rules
            for pattern, points, severity, category, desc in EXEC_RULES:
                basename = filename.rsplit("/", 1)[-1] if "/" in filename else filename
                if pattern == basename or pattern == proc_name:
                    key = f"exec:{pattern}"
                    if key not in seen_findings:
                        seen_findings.add(key)
                        score += points
                        findings.append(Finding(
                            severity=severity,
                            category=category,
                            description=desc,
                            evidence=f"execve: {proc_name} → {filename} (PID={event.pid})",
                        ))
            
            # Track non-standard process spawns
            if proc_name not in SAFE_PROCESSES:
                suspicious_execs.add(proc_name)
        
        elif event.event_type == "OPENAT":
            openat_count += 1
            filename = event.filename.strip()
            
            # Skip normal npm install file access
            if any(filename.startswith(prefix) for prefix in SAFE_FILE_PREFIXES):
                continue
            
            # Check file read rules
            for pattern, points, severity, category, desc in FILE_READ_RULES:
                if pattern in filename:
                    key = f"file:{pattern}"
                    if key not in seen_findings:
                        seen_findings.add(key)
                        score += points
                        findings.append(Finding(
                            severity=severity,
                            category=category,
                            description=desc,
                            evidence=f"openat: {event.process_name} → {filename} (PID={event.pid})",
                        ))
    
    # Bonus: excessive exec calls indicate scripted attack behavior
    expected_execs = 6  # sh, npm, node, mkdir, sleep, DT_INIT
    if execve_count > expected_execs + 5:
        extra = execve_count - expected_execs
        bonus = min(extra * 2, 20)
        score += bonus
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=Category.SUSPICIOUS_ACTIVITY,
            description=f"Unusually high process spawning: {execve_count} execve calls ({extra} more than expected)",
            evidence=f"Non-standard processes: {', '.join(sorted(suspicious_execs)) or 'none identified'}",
        ))
    
    # Cap score at 100
    score = min(score, 100)
    
    # Determine risk level
    if score >= 60:
        risk_level = RiskLevel.MALICIOUS
        recommendation = "🚫 BLOCK — Do not install this package. Multiple high-severity threat indicators detected."
    elif score >= 25:
        risk_level = RiskLevel.SUSPICIOUS
        recommendation = "⚠️ REVIEW — Package exhibits suspicious behavior. Manual review recommended before installation."
    else:
        risk_level = RiskLevel.SAFE
        recommendation = "✅ ALLOW — Package behavior appears normal for an npm install."
    
    # Sort findings by severity
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    findings.sort(key=lambda f: severity_order.get(f.severity, 5))
    
    return ThreatVerdict(
        package_name=package_name,
        detonation_id=detonation_id,
        threat_score=score,
        risk_level=risk_level,
        findings=findings,
        recommendation=recommendation,
        analysis_method="rules",
        events_analyzed=len(events),
        execve_count=execve_count,
        openat_count=openat_count,
    )


def needs_llm_analysis(verdict: ThreatVerdict) -> bool:
    """Returns True if the verdict is ambiguous and should be refined by the LLM."""
    return 11 <= verdict.threat_score <= 59
