from pathlib import Path
import re, sys
ROOT = Path(__file__).resolve().parents[1]
required = ["agent.yaml","SOUL.md","RULES.md","DUTIES.md","AGENTS.md","README.md","EXPLAINABILITY.md","requirements.txt",".env.example",".gitignore","core/__init__.py","core/auditor.py","core/cli.py","tools/inspect-access-policy.yaml","tools/analyze-permissions.yaml","tools/generate-audit-report.yaml","skills/policy-review/SKILL.md","skills/permission-analysis/SKILL.md","skills/audit-reporting/SKILL.md","tests/test_auditor.py","verification/readiness_audit.py","examples/policy_case.json"]
missing = [p for p in required if not (ROOT/p).is_file()]
if missing:
    print("FAIL: missing files: " + ", ".join(missing)); sys.exit(1)
manifest = (ROOT/"agent.yaml").read_text()
name = re.search(r"(?m)^name:\s*([^\s]+)\s*$", manifest)
if not name or not re.fullmatch(r"[a-z][a-z0-9-]*", name.group(1)):
    print("FAIL: manifest name is not normalized"); sys.exit(1)
if not all(h in (ROOT/"EXPLAINABILITY.md").read_text() for h in ("## Inputs","## Decision","## Limits")):
    print("FAIL: required explainability headings missing"); sys.exit(1)
for f in (ROOT/"tools").glob("*.yaml"):
    txt=f.read_text()
    if "input_schema:" not in txt or "additionalProperties: false" not in txt:
        print(f"FAIL: schema check failed: {f.name}"); sys.exit(1)
print("PASS: manifest name normalized")
print("PASS: flat tools listed")
print("PASS: required explainability headings")
print("PASS: strict top-level tool schemas")
print(f"PASS: {len(required)}/{len(required)} required files present")
