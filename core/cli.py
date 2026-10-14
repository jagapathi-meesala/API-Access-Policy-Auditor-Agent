import json, sys
from pathlib import Path
from .auditor import build_report, PolicyInputError

def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python -m core.cli <policy.json>", file=sys.stderr); return 2
    try:
        with Path(sys.argv[1]).open(encoding="utf-8") as f:
            data = json.load(f)
        report = build_report(data)
    except (OSError, json.JSONDecodeError, PolicyInputError) as exc:
        print(f"Input error: {exc}", file=sys.stderr); return 2
    print(json.dumps(report, indent=2))
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
