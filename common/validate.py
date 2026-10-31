"""Validate *.common.json files against common/finding.schema.json.

Usage:  python common/validate.py sast-engine/out/shop/findings.common.json dast-engine/output/x.common.json
Needs:  pip install jsonschema
Exit code 0 when every file is valid, 1 otherwise.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema

SCHEMA_PATH = Path(__file__).with_name("finding.schema.json")


def load_validator() -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    validator = load_validator()
    failed = 0
    for name in argv:
        data = json.loads(Path(name).read_text(encoding="utf-8"))
        errors = sorted(validator.iter_errors(data), key=lambda e: [str(p) for p in e.absolute_path])
        if errors:
            failed += 1
            print(f"FAIL {name}: {len(errors)} error(s)")
            for error in errors[:10]:
                where = "/".join(str(p) for p in error.absolute_path) or "<root>"
                print(f"     {where}: {error.message[:160]}")
        else:
            print(f"OK   {name}: {len(data['findings'])} {data['source']} findings")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
