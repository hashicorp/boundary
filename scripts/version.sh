#!/usr/bin/env bash
set -euo pipefail

version_file=$1
version=$(awk '$1 == "Version" && $2 == "=" { gsub(/"/, "", $3); print $3 }' < "${version_file}")
prerelease=$(awk '$1 == "VersionPrerelease" && $2 == "=" { gsub(/"/, "", $3); print $3 }' < "${version_file}")

# Return the version string with the proper license class and prerelease string
if [ -n "$(go run ./cmd/boundary/ version | grep +ent)" ]; then
    if [ -n "$prerelease" ]; then
        echo "${version}-${prerelease}+ent"
    else
        echo "${version}+ent"
    fi
else
    echo "${version}"   
fi
