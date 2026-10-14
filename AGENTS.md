# Agent Operating Notes
Use `python -m core.cli examples/policy_case.json` for the sample. Input is a JSON object with `principal`, `permissions`, `resources`, and optional `conditions`, `expires_at`, `mfa_required`, `environment`, and `notes`. Permissions are strings. Wildcard permissions/resources are treated as broad indicators, not proof of exploitability.
