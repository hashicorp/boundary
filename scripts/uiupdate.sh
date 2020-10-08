#!/bin/sh

set -e

if [ -z "$UI_VERSION_FILE" ]; then
	echo "Must set UI_VERSION_FILE"; exit 1
fi
if [ -z "$UI_CLONE_DIR" ]; then
	echo "Must set UI_CLONE_DIR"; exit 1
fi

shafileabs="$(pwd)/${UI_VERSION_FILE}"
cd "${UI_CLONE_DIR}"
V="$(git log -n1 --pretty=oneline)"
echo "==> Setting UI version to: $V"

# Write the version file.
{
	echo "$V"
	echo "# This file determines the version of the UI to embed in the boundary binary."
	echo "# Update this file by running 'make update-ui-version' from the root of this repo."
	echo "# Set UI_COMMITISH when running the above target to update to a specific version."
} > "${shafileabs}"
