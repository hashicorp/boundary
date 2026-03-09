#!/usr/bin/env bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

#
# This script builds the application from source for a single platform.
set -e

GO_CMD=${GO_CMD:-go}

# Get the parent directory of where this script is.
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )/.." && pwd )"

# Change into that directory
cd "$DIR"

# Set build tags
BUILD_TAGS="${BUILD_TAGS:-"boundary"}"
echo "==> Build tags: ${BUILD_TAGS}"

# Get the git commit
GIT_COMMIT="$(git rev-parse HEAD)"
GIT_DIRTY="$(test -n "`git status --porcelain`" && echo "+CHANGES" || true)"

# Get the build date from the latest commit since it can be used across all
# builds
function build_date() {
  # It's tricky to do an RFC3339 format in a cross platform way, so we hardcode UTC
  : "${DATE_FORMAT:="%Y-%m-%dT%H:%M:%SZ"}"
  git show --no-show-signature -s --format=%cd --date=format:"$DATE_FORMAT" HEAD
}
BUILD_DATE=$(build_date)

# If not explicitly cross-compiling, build for the current platform
if [ "${GOOS}x" == "x" ]; then
    GOOS=$(go env GOOS)
fi
if [ "${GOARCH}x" == "x" ]; then
    GOARCH=$(go env GOARCH)
fi

GOPATH=${GOPATH:-$(go env GOPATH)}
case $(uname) in
    CYGWIN*)
        GOPATH="$(cygpath $GOPATH)"
        ;;
esac

BINARY_SUFFIX=""
if [ "${GOOS}x" = "windowsx" ]; then
    BINARY_SUFFIX=".exe"
fi

# Build needed plugins first
if [ "${SKIP_PLUGIN_BUILD}x" == "x" ]; then
    $DIR/scripts/plugins.sh
fi

BASE_PRODUCT_VERSION=${BASE_PRODUCT_VERSION:=$(cat version/VERSION)}

# Declare binary paths!
BINARY_NAME="boundary${BINARY_SUFFIX}"
BIN_PATH=${BIN_PATH:=bin/${BINARY_NAME}}
BIN_PARENT_DIR="${BIN_PATH%/*}"
BIN_PARENT_DIR="${BIN_PARENT_DIR##*/}"

# Delete the old dir
echo "==> Removing old directory ${BIN_PARENT_DIR}..."
rm -rf ${BIN_PARENT_DIR}
mkdir -p ${BIN_PARENT_DIR}

# Build!
echo "==> Building into ${BIN_PARENT_DIR} for ${GOOS}_${GOARCH}..."
${GO_CMD} build \
    -tags="${BUILD_TAGS}" \
    -trimpath \
    -buildvcs=false \
    -ldflags "
      -X 'github.com/hashicorp/boundary/version.GitCommit=${GIT_COMMIT}${GIT_DIRTY}'
      -X 'github.com/hashicorp/boundary/version.Version=$BASE_PRODUCT_VERSION'
      -X 'github.com/hashicorp/boundary/version.VersionPrerelease=$PRERELEASE_PRODUCT_VERSION'
      -X 'github.com/hashicorp/boundary/version.VersionMetadata=$METADATA_PRODUCT_VERSION'
      -X 'github.com/hashicorp/boundary/version.BuildDate=$BUILD_DATE'
      " \
    -o "$BIN_PATH" \
    ./cmd/boundary

# Copy binary into gopath if desired
if [ "${BOUNDARY_INSTALL_BINARY}x" != "x" ]; then
    echo "==> Moving binary into GOPATH/bin..."
    mv -f "${BIN_PATH}" "${GOPATH}/bin/"
fi

cp LICENSE "${BIN_PARENT_DIR}/LICENSE.txt"

# Done!
echo "==> Results:"
ls -hl ${BIN_PARENT_DIR}
