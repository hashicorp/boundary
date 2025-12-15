#!/bin/bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

set -eux -o pipefail

env

# Requirements
npm install --global pnpm || true

# Go to the root of the boundary repo
root_dir="$(git rev-parse --show-toplevel)"
pushd "${root_dir}" > /dev/null

export UI_SRC_OVERRIDE="${UI_BUILD_OVERRIDE}"
make ${BUILD_TARGET}
zip -j ${ARTIFACT_PATH}/${ARTIFACT_NAME}.zip bin/${BINARY_NAME}

popd > /dev/null
