#!/usr/bin/env bash
set -euo pipefail

# set matrix var to list of unique packages containing tests
matrix="$(go list -json="ImportPath,TestGoFiles" ./... | jq --compact-output '. | select(.TestGoFiles != null) | .ImportPath | split("\n")')"

echo "matrix=${matrix}" | tee -a "${GITHUB_OUTPUT}"