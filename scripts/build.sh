#!/usr/bin/env bash
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

if [ "${CI_BUILD}x" != "x" ]; then
    source /home/circleci/.bashrc
fi

# Set build tags
BUILD_TAGS="${BUILD_TAGS:-"boundary"}"
echo "==> Build tags: ${BUILD_TAGS}"

# Get the git commit
GIT_COMMIT="$(git rev-parse HEAD)"
GIT_DIRTY="$(test -n "`git status --porcelain`" && echo "+CHANGES" || true)"

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

if [ "${CI_BUILD}x" != "x" ]; then
    exit
fi

# Delete the old dir
echo "==> Removing old directory..."
rm -f bin/*
mkdir -p bin/

# Build!
echo "==> Building into bin/ for ${GOOS}_${GOARCH}..."
BINARY_NAME="boundary${BINARY_SUFFIX}"
${GO_CMD} build \
    -tags="${BUILD_TAGS}" \
    -ldflags "-X github.com/hashicorp/boundary/version.GitCommit=${GIT_COMMIT}${GIT_DIRTY}" \
    -o "bin/${BINARY_NAME}" \
    ./cmd/boundary

# Copy binary into gopath if desired
if [ "${BOUNDARY_INSTALL_BINARY}x" != "x" ]; then
    echo "==> Moving binary into GOPATH/bin..."
    mv -f "bin/${BINARY_NAME}" "${GOPATH}/bin/"
fi

# Done!
echo "==> Results:"
ls -hl bin/