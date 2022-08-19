#!/bin/bash
set -eux -o pipefail

env

# Requirements
npm install --global yarn || true

# Go to the root of the boundary repo
root_dir="$(git rev-parse --show-toplevel)"
pushd "${root_dir}" > /dev/null

make build-ui
make build
zip -j ${ARTIFACT_PATH}/boundary.zip bin/boundary

popd > /dev/null
