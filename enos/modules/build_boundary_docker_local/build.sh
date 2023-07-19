#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -eux -o pipefail

# Go to the root of the boundary repo
root_dir="$(git rev-parse --show-toplevel)"
pushd "${root_dir}" > /dev/null

export IMAGE_TAG_DEV="${IMAGE_NAME}"
make build-ui docker-build-dev

popd > /dev/null
