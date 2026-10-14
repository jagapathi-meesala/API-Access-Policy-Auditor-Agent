from __future__ import annotations
from typing import Any

REQUIRED = {"principal", "permissions", "resources"}

class PolicyInputError(ValueError):
    pass

def normalize_policy(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise PolicyInputError("Policy must be a JSON object.")
    missing = sorted(REQUIRED - data.keys())
    if missing:
        raise PolicyInputError("Missing required fields: " + ", ".join(missing))
    if not isinstance(data["principal"], str) or not data["principal"].strip():
        raise PolicyInputError("principal must be a non-empty string")
    for field in ("permissions", "resources"):
        if not isinstance(data[field], list) or any(not isinstance(x, str) for x in data[field]):
            raise PolicyInputError(f"{field} must be a list of strings")
    conditions = data.get("conditions", {})
    if not isinstance(conditions, dict):
        raise PolicyInputError("conditions must be an object when supplied")
    env = data.get("environment", "unknown")
    if not isinstance(env, str):
        raise PolicyInputError("environment must be a string")
    return {
        "principal": data["principal"].strip(),
        "permissions": sorted(set(p.strip() for p in data["permissions"] if p.strip())),
        "resources": sorted(set(r.strip() for r in data["resources"] if r.strip())),
        "conditions": conditions,
        "expires_at": data.get("expires_at"),
        "mfa_required": data.get("mfa_required"),
        "environment": env.lower(),
        "notes": data.get("notes", ""),
    }

def analyze_policy(policy: dict[str, Any]) -> list[dict[str, str]]:
    p = normalize_policy(policy)
    findings: list[dict[str, str]] = []
    def add(rule: str, severity: str, title: str, evidence: str, recommendation: str) -> None:
        findings.append({"rule_id": rule, "severity": severity, "title": title, "evidence": evidence, "recommendation": recommendation})
    perms, resources = p["permissions"], p["resources"]
    if not perms:
        add("AP-001", "high", "No explicit permissions", "permissions is empty", "Define the minimum required actions explicitly.")
    if any(x == "*" or x.endswith(":*") or x.lower() in {"admin", "administrator", "root"} for x in perms):
        add("AP-002", "high", "Broad or administrative permission", ", ".join(perms), "Replace broad grants with narrowly scoped actions and review necessity.")
    if any("write" in x.lower() or "delete" in x.lower() or "admin" in x.lower() or "manage" in x.lower() for x in perms) and p["environment"] == "production":
        add("AP-003", "high", "Privileged access in production", ", ".join(perms), "Confirm business need; separate read and change roles and add approval/audit controls.")
    if not resources:
        add("AP-004", "high", "Resource scope missing", "resources is empty", "Specify the smallest set of resources this principal needs.")
    elif any(x == "*" or x.endswith("/*") for x in resources):
        add("AP-005", "medium", "Broad resource scope", ", ".join(resources), "Narrow resource patterns where supported and document unavoidable broad scope.")
    conditions = p["conditions"]
    if conditions.get("source_network_restricted") is False:
        add("AP-006", "medium", "Network restriction explicitly disabled", "conditions.source_network_restricted=false", "Restrict access by network or use an appropriate stronger contextual control.")
    elif "source_network_restricted" not in conditions:
        add("AP-007", "low", "Network restriction not documented", "conditions.source_network_restricted is absent", "Verify whether network restrictions or equivalent controls apply.")
    privileged = any(x == "*" or any(k in x.lower() for k in ("admin", "write", "delete", "manage")) for x in perms)
    if privileged and p["mfa_required"] is False:
        add("AP-008", "high", "MFA explicitly disabled for privileged access", "mfa_required=false", "Require strong authentication where supported, especially for human or interactive privileged access.")
    elif privileged and p["mfa_required"] is None:
        add("AP-009", "medium", "MFA requirement not documented", "mfa_required is absent or null", "Verify authentication controls; use workload identity controls for non-human principals where MFA is not applicable.")
    if not p["expires_at"]:
        add("AP-010", "low", "No access expiry supplied", "expires_at is missing, null, or empty", "Consider time-bounded grants and periodic access review.")
    return findings

def build_report(policy: dict[str, Any]) -> dict[str, Any]:
    p = normalize_policy(policy)
    findings = analyze_policy(p)
    weights = {"high": 3, "medium": 2, "low": 1}
    score = min(100, sum(weights[f["severity"]] for f in findings) * 8)
    rank = "high" if score >= 48 else "medium" if score >= 24 else "low"
    return {
        "agent": "api-access-policy-auditor-agent",
        "principal": p["principal"],
        "environment": p["environment"],
        "finding_count": len(findings),
        "triage_score": score,
        "triage_level": rank,
        "findings": findings,
        "limitations": ["Generic heuristic checks only; provider-specific semantics and inherited controls are not evaluated.", "Findings are review indicators, not proof of exploitability or compliance status."],
        "recommended_next_step": "Have the policy owner validate findings against the deployed configuration and approve changes before rollout."
    }
