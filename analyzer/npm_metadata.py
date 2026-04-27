"""npm registry metadata enrichment.

Queries the npm registry API to gather package intelligence BEFORE detonation:
- Publish date (flag if < 7 days old)
- Weekly download count (flag if < 100)
- Number of maintainers
- Version count
- Name similarity to popular packages (typosquatting detection)
"""

import json
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError

from .models import Finding, Severity, Category


# Popular packages that are common typosquatting targets
POPULAR_PACKAGES = {
    "lodash", "express", "react", "axios", "chalk", "commander",
    "moment", "request", "debug", "async", "underscore", "bluebird",
    "uuid", "webpack", "typescript", "eslint", "prettier", "jest",
    "mocha", "yargs", "glob", "minimist", "dotenv", "cors",
    "body-parser", "mongoose", "sequelize", "passport", "socket.io",
    "nodemon", "pm2", "next", "nuxt", "vue", "angular", "svelte",
    "electron", "puppeteer", "cheerio", "sharp", "bcrypt",
    "jsonwebtoken", "crypto-js", "node-fetch", "form-data",
}


def _levenshtein(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    
    return prev_row[-1]


def fetch_metadata(package_name: str) -> dict | None:
    """Fetch package metadata from the npm registry.
    
    Returns a dict with parsed metadata, or None on failure.
    """
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        req = Request(url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except (URLError, json.JSONDecodeError, OSError):
        return None


def fetch_downloads(package_name: str) -> int | None:
    """Fetch weekly download count from npm."""
    url = f"https://api.npmjs.org/downloads/point/last-week/{package_name}"
    try:
        req = Request(url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return data.get("downloads", 0)
    except (URLError, json.JSONDecodeError, OSError):
        return None


def analyze_metadata(package_name: str) -> tuple[list[Finding], dict]:
    """Analyze npm registry metadata for suspicious signals.
    
    Returns:
        Tuple of (findings, metadata_summary dict).
    """
    findings: list[Finding] = []
    summary: dict = {"package": package_name, "available": False}
    
    # Fetch registry data
    meta = fetch_metadata(package_name)
    if meta is None:
        summary["error"] = "Could not fetch from npm registry"
        return findings, summary
    
    # Check if package exists on npm
    if "error" in meta:
        summary["error"] = meta.get("error", "Not found")
        # Not on npm — could be a local/private package
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=Category.SUSPICIOUS_ACTIVITY,
            description=f"Package '{package_name}' not found on npm registry",
            evidence="Not published to npm — could be private or newly created",
            mitre_id="T1195.002",
            mitre_name="Supply Chain Compromise: Compromise Software Supply Chain",
        ))
        return findings, summary
    
    summary["available"] = True
    
    # Extract metadata
    dist_tags = meta.get("dist-tags", {})
    latest_version = dist_tags.get("latest", "unknown")
    versions = meta.get("versions", {})
    time_data = meta.get("time", {})
    maintainers = meta.get("maintainers", [])
    
    summary["latest_version"] = latest_version
    summary["total_versions"] = len(versions)
    summary["maintainers"] = len(maintainers)
    summary["maintainer_names"] = [m.get("name", "?") for m in maintainers[:5]]
    
    # Check publish date of latest version
    if latest_version in time_data:
        try:
            publish_str = time_data[latest_version]
            publish_date = datetime.fromisoformat(publish_str.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - publish_date).days
            summary["latest_published"] = publish_str
            summary["age_days"] = age_days
            
            if age_days < 7:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=Category.SUSPICIOUS_ACTIVITY,
                    description=f"Package version published {age_days} days ago (very recent)",
                    evidence=f"Latest version {latest_version} published {publish_str}",
                    mitre_id="T1195.002",
                    mitre_name="Supply Chain Compromise: Compromise Software Supply Chain",
                ))
            elif age_days < 30:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.SUSPICIOUS_ACTIVITY,
                    description=f"Package version published {age_days} days ago (relatively new)",
                    evidence=f"Latest version {latest_version} published {publish_str}",
                    mitre_id="T1195.002",
                    mitre_name="Supply Chain Compromise: Compromise Software Supply Chain",
                ))
        except (ValueError, TypeError):
            pass
    
    # Check download count
    downloads = fetch_downloads(package_name)
    if downloads is not None:
        summary["weekly_downloads"] = downloads
        if downloads < 100:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=Category.SUSPICIOUS_ACTIVITY,
                description=f"Very low download count: {downloads} weekly downloads",
                evidence=f"Popular packages typically have 10,000+ weekly downloads",
                mitre_id="T1195.002",
                mitre_name="Supply Chain Compromise: Compromise Software Supply Chain",
            ))
        elif downloads < 1000:
            findings.append(Finding(
                severity=Severity.LOW,
                category=Category.SUSPICIOUS_ACTIVITY,
                description=f"Low download count: {downloads} weekly downloads",
                evidence="Relatively unpopular package",
                mitre_id="T1195.002",
                mitre_name="Supply Chain Compromise: Compromise Software Supply Chain",
            ))
    
    # Check maintainer count
    if len(maintainers) <= 1:
        findings.append(Finding(
            severity=Severity.LOW,
            category=Category.SUSPICIOUS_ACTIVITY,
            description=f"Single maintainer package",
            evidence=f"Maintainer: {maintainers[0].get('name', '?') if maintainers else 'unknown'}",
            mitre_id="T1195.002",
            mitre_name="Supply Chain Compromise: Compromise Software Supply Chain",
        ))
    
    # Check typosquatting
    for popular in POPULAR_PACKAGES:
        if package_name == popular:
            break  # It IS the popular package
        distance = _levenshtein(package_name.lower(), popular.lower())
        if 0 < distance <= 2:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=Category.SUSPICIOUS_ACTIVITY,
                description=f"Package name '{package_name}' is similar to popular package '{popular}' (possible typosquatting)",
                evidence=f"Levenshtein distance: {distance}",
                mitre_id="T1195.002",
                mitre_name="Supply Chain Compromise: Compromise Software Supply Chain",
            ))
            summary["typosquat_target"] = popular
            break
    
    return findings, summary
