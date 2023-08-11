#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1


set -e

if [ -z "$UI_CLONE_DIR" ]; then
	echo "Must set UI_CLONE_DIR"; exit 1
fi

if [ -z "$UI_VERSION_FILE" ]; then
	echo "Must set UI_VERSION_FILE"; exit 1
fi

UI_EDITION=$(make --no-print-directory edition)

if [ "$UI_EDITION" == "oss" ]; then
  UI_REPO=https://github.com/hashicorp/boundary-ui
  REPO_NAME=boundary-ui
else
  UI_VERSION_FILE="${UI_VERSION_FILE}_ent"
  UI_REPO=https://github.com/hashicorp/boundary-ui-enterprise
  REPO_NAME=boundary-ui-enterprise
fi

UI_CURRENT_COMMIT=$(head -n1 < "${UI_VERSION_FILE}" | cut -d' ' -f1)

if [ -z "$UI_COMMITISH" ]; then
  echo "==> Building default UI version from $UI_VERSION_FILE: $UI_CURRENT_COMMIT"
  export UI_COMMITISH="$UI_CURRENT_COMMIT"
else
  echo "==> Building custom UI version $UI_COMMITISH"
fi;

if which gh &> /dev/null;  then
    echo "Found gh cli, attempting to download ui assets"

    artifact_id=$(gh api "repos/hashicorp/${REPO_NAME}/actions/artifacts" --paginate | \
        jq ".artifacts[] | select(.workflow_run.head_sha == \"${UI_COMMITISH}\" and .name == \"admin-ui-${UI_EDITION}\")" | \
        jq -r '.id')

    if [[ ${artifact_id} ]]; then
        echo "Downloading artifact: ${artifact_id} for admin-ui-${UI_EDITION} ${UI_COMMITISH}"
        tmp_dir=$(mktemp -d)
        gh api "repos/hashicorp/${REPO_NAME}/actions/artifacts/${artifact_id}/zip" > "${tmp_dir}/boundary-ui.zip"
        trap 'rm -rf ${tmp_dir}' EXIT

        # remove any previous artifact download or git clone
        rm -rf "${UI_CLONE_DIR}"

        mkdir -p "${UI_CLONE_DIR}/ui/admin/dist"
        unzip "${tmp_dir}/boundary-ui.zip" -d "${UI_CLONE_DIR}/ui/admin/dist"
        exit $?
    else
        echo "could not find artifact: admin-ui-${UI_EDITION} ${UI_COMMITISH}, falling back to git clone"
    fi
fi

if ! which yarn &> /dev/null; then
    echo "Yarn must be installed to build ui assets from a git clone.\nPlease ensure Node v14+ and Yarn v1.22.10+ are installed."
    exit 1
fi

tempdir="$(dirname "${UI_CLONE_DIR}")"

mkdir -p "${tempdir}"
echo "*" > "${tempdir}/.gitignore"

if ! [ -d "${UI_CLONE_DIR}/.git" ]; then
    # clear out dir, incase it was previously an artifact download
    rm -rf "${UI_CLONE_DIR}"
	git clone "${UI_REPO}" "${UI_CLONE_DIR}"
fi

pushd "${UI_CLONE_DIR}"
git reset --hard
git fetch origin "${UI_COMMITISH}"
git checkout "${UI_COMMITISH}"
git pull --ff-only origin "${UI_COMMITISH}"
git reset --hard "${UI_COMMITISH}"

yarn install
EDITION=${UI_EDITION} yarn build
popd
