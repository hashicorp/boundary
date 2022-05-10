#!/bin/sh

set -e

if [ -z "$UI_VERSION_FILE" ]; then
	echo "Must set UI_VERSION_FILE"; exit 1
fi

shafileabs="$(pwd)/${UI_VERSION_FILE}"
V="$(git ls-remote https://github.com/hashicorp/boundary-ui main)"
SHA=${V:0:40}
echo "==> Setting UI version to: $SHA"

# Write the version file.
{
	echo "$SHA"
	echo "# This file determines the version of the UI to embed in the boundary binary."
	echo "# Update this file by running 'make update-ui-version' from the root of this repo."
	echo "# Set UI_COMMITISH when running the above target to update to a specific version."
} > "${shafileabs}"
