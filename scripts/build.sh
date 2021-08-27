#!/usr/bin/env bash
#
# This script builds the application from source for a single platform.
set -e

# Get the parent directory of where this script is.
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )/.." && pwd )"

# Change into that directory
cd "$DIR"

# Set build tags
BUILD_TAGS="${BUILD_TAGS:-"boundary"}"

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
if [ "${GOOS}x" == "windowsx" ]; then
    BINARY_SUFFIX=".exe"
fi

# Build needed plugins first
ORIG_PATH=$(pwd);
for PLUGIN_TYPE in kms; do
    rm -f $ORIG_PATH/plugins/$PLUGIN_TYPE/assets/boundary-plugin-${PLUGIN_TYPE}*
    for CURR_PLUGIN in $(ls $ORIG_PATH/plugins/$PLUGIN_TYPE/mains); do
        cd $ORIG_PATH/plugins/$PLUGIN_TYPE/mains/$CURR_PLUGIN;
        go build -v -o $ORIG_PATH/plugins/$PLUGIN_TYPE/assets/boundary-plugin-${PLUGIN_TYPE}-${CURR_PLUGIN}${BINARY_SUFFIX} .;
        cd $ORIG_PATH;
    done;
    cd $ORIG_PATH/plugins/$PLUGIN_TYPE/assets;
    for CURR_PLUGIN in $(ls); do
        gzip -f -9 $CURR_PLUGIN;
    done;
    cd $ORIG_PATH;
done;

# Delete the old dir
echo "==> Removing old directory..."
rm -f bin/*
mkdir -p bin/

# Build!
echo "==> Building..."
go build -tags="${BUILD_TAGS}" \
    -ldflags "-X github.com/hashicorp/boundary/version.GitCommit=${GIT_COMMIT}${GIT_DIRTY}" \
    -o "bin/${BINARY_NAME}" \
    ./cmd/boundary

# Done!
echo "==> Done!"
