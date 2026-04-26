"""NPM Detonator — AI Threat Analyst

Standalone service that consumes syscall telemetry from Kafka,
scores packages using rule-based analysis + Gemini LLM, and
outputs structured ThreatVerdict reports.

Usage:
    python -m analyzer
"""
