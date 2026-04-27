"""Pre-detonation static source code scanner.

Analyzes npm package source code BEFORE detonation to catch red flags
that don't require runtime execution to identify:
- postinstall/preinstall hooks in package.json
- Obfuscated code patterns (eval, Buffer.from, hex strings)
- Hardcoded suspicious URLs and IP addresses
- Sensitive file path references in source
- child_process / execSync usage
"""

import json
import os
import re
import tarfile
import tempfile
from pathlib import Path

from .models import Finding, Severity, Category


# ──────────────────────────────────────────────────────────────
# Pattern Definitions
# ──────────────────────────────────────────────────────────────

# Dangerous package.json script hooks
DANGEROUS_HOOKS = {"preinstall", "postinstall", "preuninstall", "postuninstall", "install"}

# Code patterns that indicate obfuscation or malicious intent
CODE_PATTERNS = [
    # Obfuscation
    (r'\beval\s*\(', Severity.HIGH, Category.SUSPICIOUS_ACTIVITY,
     "Uses eval() — common obfuscation technique",
     "T1027", "Obfuscated Files or Information"),
    (r'Buffer\.from\s*\([^)]*,\s*["\'](?:base64|hex)["\']', Severity.HIGH, Category.SUSPICIOUS_ACTIVITY,
     "Decodes base64/hex data at runtime — possible obfuscated payload",
     "T1027", "Obfuscated Files or Information"),
    (r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}', Severity.MEDIUM, Category.SUSPICIOUS_ACTIVITY,
     "Contains long hex-encoded string — possible obfuscated code",
     "T1027", "Obfuscated Files or Information"),
    (r'atob\s*\(', Severity.MEDIUM, Category.SUSPICIOUS_ACTIVITY,
     "Uses atob() to decode base64 data",
     "T1027", "Obfuscated Files or Information"),
    (r'Function\s*\(', Severity.HIGH, Category.SUSPICIOUS_ACTIVITY,
     "Dynamic function construction via Function() — code injection risk",
     "T1059", "Command and Scripting Interpreter"),

    # Process execution
    (r'child_process', Severity.MEDIUM, Category.SUSPICIOUS_ACTIVITY,
     "Imports child_process module — can execute arbitrary commands",
     "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    (r'execSync\s*\(', Severity.HIGH, Category.SUSPICIOUS_ACTIVITY,
     "Uses execSync() — synchronous command execution",
     "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    (r'exec\s*\(', Severity.MEDIUM, Category.SUSPICIOUS_ACTIVITY,
     "Uses exec() — asynchronous command execution",
     "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    (r'spawn\s*\(', Severity.MEDIUM, Category.SUSPICIOUS_ACTIVITY,
     "Uses spawn() — process spawning",
     "T1059.004", "Command and Scripting Interpreter: Unix Shell"),

    # Network
    (r'https?://[^\s"\']+(?:evil|attacker|malware|c2|exfil)', Severity.CRITICAL, Category.DATA_EXFILTRATION,
     "Hardcoded URL with suspicious keywords (evil/attacker/c2)",
     "T1071.001", "Application Layer Protocol: Web Protocols"),
    (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', Severity.HIGH, Category.NETWORK,
     "Hardcoded IP address URL — possible C2 endpoint",
     "T1071.001", "Application Layer Protocol: Web Protocols"),

    # File system
    (r'/etc/shadow', Severity.CRITICAL, Category.CREDENTIAL_THEFT,
     "References /etc/shadow in source code",
     "T1003.008", "OS Credential Dumping: /etc/shadow"),
    (r'\.ssh/id_rsa', Severity.CRITICAL, Category.CREDENTIAL_THEFT,
     "References SSH private key in source code",
     "T1552.004", "Unsecured Credentials: Private Keys"),
    (r'/etc/crontab', Severity.HIGH, Category.PERSISTENCE,
     "References crontab in source code — persistence mechanism",
     "T1053.003", "Scheduled Task/Job: Cron"),
    (r'\.npmrc', Severity.MEDIUM, Category.CREDENTIAL_THEFT,
     "References .npmrc — may steal npm auth tokens",
     "T1552.001", "Unsecured Credentials: Credentials in Files"),
    (r'writeFileSync|appendFileSync', Severity.MEDIUM, Category.PERSISTENCE,
     "Writes files synchronously — may modify system files",
     "T1565.001", "Data Manipulation: Stored Data Manipulation"),
]

# File extensions to scan
SCANNABLE_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".sh", ".py", ".rb"}


def scan_directory(package_dir: str) -> list[Finding]:
    """Scan a package directory for suspicious patterns.
    
    Args:
        package_dir: Path to the extracted package directory.
    
    Returns:
        List of Finding objects for detected issues.
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    package_path = Path(package_dir)
    
    # 1. Check package.json for dangerous hooks
    pkg_json_path = package_path / "package.json"
    if pkg_json_path.exists():
        try:
            pkg_data = json.loads(pkg_json_path.read_text())
            scripts = pkg_data.get("scripts", {})
            for hook in DANGEROUS_HOOKS:
                if hook in scripts:
                    key = f"hook:{hook}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            category=Category.SUSPICIOUS_ACTIVITY,
                            description=f"package.json has '{hook}' script: {scripts[hook]}",
                            evidence=f"scripts.{hook} = \"{scripts[hook]}\"",
                            mitre_id="T1204.002",
                            mitre_name="User Execution: Malicious File",
                        ))
        except (json.JSONDecodeError, OSError):
            pass
    
    # 2. Scan source files for suspicious patterns
    for filepath in package_path.rglob("*"):
        if filepath.is_dir():
            continue
        if filepath.suffix not in SCANNABLE_EXTENSIONS:
            continue
        # Skip node_modules
        if "node_modules" in filepath.parts:
            continue
        
        try:
            content = filepath.read_text(errors="ignore")
        except OSError:
            continue
        
        relative = filepath.relative_to(package_path)
        
        for pattern, severity, category, desc, mitre_id, mitre_name in CODE_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                key = f"code:{pattern}:{relative}"
                if key not in seen:
                    seen.add(key)
                    # Find the line number of the first match
                    for i, line in enumerate(content.split("\n"), 1):
                        if re.search(pattern, line):
                            line_preview = line.strip()[:80]
                            findings.append(Finding(
                                severity=severity,
                                category=category,
                                description=desc,
                                evidence=f"{relative}:{i} → {line_preview}",
                                mitre_id=mitre_id,
                                mitre_name=mitre_name,
                            ))
                            break
    
    # Sort by severity
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    findings.sort(key=lambda f: severity_order.get(f.severity, 5))
    
    return findings


def scan_tarball(tarball_path: str) -> list[Finding]:
    """Extract and scan a .tgz package tarball.
    
    Args:
        tarball_path: Path to the .tgz file.
    
    Returns:
        List of Finding objects.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        with tarfile.open(tarball_path, "r:gz") as tar:
            tar.extractall(tmpdir, filter="data")
        
        # npm tarballs typically extract to a 'package/' subdirectory
        package_subdir = os.path.join(tmpdir, "package")
        if os.path.isdir(package_subdir):
            return scan_directory(package_subdir)
        
        # Fallback: scan the entire extracted directory
        return scan_directory(tmpdir)


def scan_package(path: str) -> list[Finding]:
    """Auto-detect whether path is a directory or tarball and scan it.
    
    Args:
        path: Path to package directory or .tgz file.
    
    Returns:
        List of Finding objects.
    """
    if os.path.isdir(path):
        return scan_directory(path)
    elif path.endswith(".tgz") or path.endswith(".tar.gz"):
        return scan_tarball(path)
    else:
        return []
