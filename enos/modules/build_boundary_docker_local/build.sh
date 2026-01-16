#!/usr/bin/env bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

set -eux -o pipefail

# Go to the root of the boundary repo
root_dir="$(git rev-parse --show-toplevel)"
pushd "${root_dir}" > /dev/null

# make docker image
export DEV_DOCKER_GOARCH=$(uname -m)
# x86_64 is the output of `uname -m` on github actions runners
# but the go requires goarch to be amd64
if [[ $DEV_DOCKER_GOARCH == "x86_64" ]]; then
   export DEV_DOCKER_GOARCH="amd64"
fi
export UI_SRC_OVERRIDE="${UI_BUILD_OVERRIDE}"
export IMAGE_TAG_DEV="${IMAGE_NAME}"
make build-ui docker-build-dev

# make the cli to be used by the test runner
export GOOS=linux
make build
zip -j ${ARTIFACT_PATH}/boundary.zip bin/boundary

popd > /dev/null
