#!/bin/sh

set -e

if [ -z "$UI_COMMITISH" ]; then
	echo "Must set UI_COMMITISH"; exit 1
fi

if [ -z "$UI_CLONE_DIR" ]; then
	echo "Must set UI_CLONE_DIR"; exit 1
fi

if [ -z "$UI_VERSION_FILE" ]; then
	echo "Must set UI_CLONE_DIR"; exit 1
fi

tempdir="$(dirname "${UI_CLONE_DIR}")"

mkdir -p "${tempdir}"
echo "*" > "${tempdir}/.gitignore"

if ! [ -d "${UI_CLONE_DIR}/.git" ]; then
	git clone https://github.com/hashicorp/boundary-ui "${UI_CLONE_DIR}"
fi

cd "${UI_CLONE_DIR}"
git reset --hard
git fetch origin "${UI_COMMITISH}"
git checkout "${UI_COMMITISH}"
git pull --ff-only origin "${UI_COMMITISH}"
git reset --hard "${UI_COMMITISH}"
