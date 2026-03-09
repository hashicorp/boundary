#!/usr/bin/env bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1


set -e

if [ -z "$UI_VERSION_FILE" ]; then
	echo "Must set UI_VERSION_FILE"; exit 1
fi

if [ -z "$UI_COMMITISH" ]; then
	echo "Must set UI_COMMITISH"; exit 1
fi

UI_EDITION=$(make --no-print-directory edition)

if [ "$UI_EDITION" == "oss" ]; then
  UI_REPO=https://github.com/hashicorp/boundary-ui
else
  UI_VERSION_FILE="${UI_VERSION_FILE}_ent"
  UI_REPO=https://github.com/hashicorp/boundary-ui-enterprise
fi

shafileabs="$(pwd)/${UI_VERSION_FILE}"
V="$(git ls-remote ${UI_REPO} ${UI_COMMITISH})"

if [ -z "$V" ]; then
	V=$UI_COMMITISH;
fi

SHA=${V:0:40}
echo "==> Setting UI version to: $SHA"

# Write the version file.
{
	echo "$SHA"
	echo "# This file determines the version of the UI to embed in the boundary binary."
	echo "# Update this file by running 'make update-ui-version' from the root of this repo."
	echo "# Set UI_COMMITISH when running the above target to update to a specific version."
} > "${shafileabs}"
