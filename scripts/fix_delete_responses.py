#!/usr/bin/env python3
# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1
#
# Post-processes the generated OpenAPI v2 spec to remove the default 200
# response from delete operations and ensure only 204 is advertised.
#
# Background: protoc-gen-openapiv2 always emits a default 200 response
# based on the RPC return type. There is no annotation-level way to suppress
# it for specific operations. This script runs after buf generate and
# performs the targeted fix.
#
# Usage:
#   python3 scripts/fix_delete_responses.py
# Or as part of the generation pipeline:
#   buf generate --template buf.openapiv2.gen.yaml internal/proto && python3 scripts/fix_delete_responses.py

import json
import sys
from pathlib import Path

SPEC_PATH = Path(__file__).parent.parent / "internal" / "gen" / "controller.swagger.json"


def fix_delete_responses(spec_path: Path) -> None:
    if not spec_path.exists():
        print(f"ERROR: spec file not found at {spec_path}", file=sys.stderr)
        print("Run 'buf generate --template buf.openapiv2.gen.yaml internal/proto' first.", file=sys.stderr)
        sys.exit(1)

    with open(spec_path) as f:
        spec = json.load(f)

    paths = spec.get("paths", {})
    fixed = 0

    for path, methods in paths.items():
        if "delete" not in methods:
            continue

        delete_op = methods["delete"]
        responses = delete_op.get("responses", {})

        if "200" in responses and "204" in responses:
            del responses["200"]
            fixed += 1
            print(f"  Fixed: DELETE {path}  (removed 200, kept 204)")
        elif "200" in responses and "204" not in responses:
            # 204 annotation missing — warn but don't remove 200
            print(f"  WARNING: DELETE {path} has 200 but no 204 — skipping (check proto annotation)")
        elif "204" in responses and "200" not in responses:
            print(f"  OK:    DELETE {path}  (204 already correct)")

    with open(spec_path, "w") as f:
        json.dump(spec, f, indent=2)
        f.write("\n")

    print(f"\nDone. Fixed {fixed} delete operation(s) in {spec_path}")


if __name__ == "__main__":
    print(f"Post-processing {SPEC_PATH} ...")
    fix_delete_responses(SPEC_PATH)
