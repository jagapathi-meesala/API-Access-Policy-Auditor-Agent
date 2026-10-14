# API Access Policy Auditor Agent

An explainable, local-first policy review helper that flags potentially excessive API permissions, wildcard scopes, missing contextual controls, absent expiry, and risky administrative access. It analyzes supplied JSON only; it does not call APIs, test credentials, or change policies.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
python3 verification/readiness_audit.py
python3 -m core.cli examples/policy_case.json
```

## Input format

```json
{
  "principal": "service:reporting-job",
  "permissions": ["records:read", "records:write"],
  "resources": ["records/*"],
  "conditions": {"source_network_restricted": false},
  "expires_at": null,
  "mfa_required": false,
  "environment": "production",
  "notes": "Example only; no real credentials"
}
```

## Findings

The report includes a score for triage, severity-labelled findings, evidence, rationale, and suggested remediation. The score is a heuristic prioritization aid, not a probability or compliance grade. Missing fields are treated as unknown unless the rule explicitly flags their absence.

## Safety and limits

- Never include real API keys, bearer tokens, passwords, or private keys in examples.
- A finding indicates a review concern, not proof of an exploitable vulnerability.
- Policy syntax and semantics differ by API gateway, cloud provider, and identity platform; validate against the relevant official schema and runtime behavior.
- This tool does not provide legal, regulatory, or formal compliance certification.
- Review proposed changes with the system owner and test in a controlled environment.

## OpenGAP

The manifest and project layout are OpenGAP-style. Official OpenGAP CLI validation must be run separately if required by your submission track.
