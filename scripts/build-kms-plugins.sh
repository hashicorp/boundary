#!/usr/bin/env bash
#
# This script builds the application from source for multiple platforms.
set -ex

# Get the parent directory of where this script is.
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )/.." && pwd )"

# Change into that directory
cd "$DIR"

PLUGINS_DIR="${DIR}/sdk/kms/plugins"
ASSETS_DIR="${DIR}/sdk/kms/assets"
ASSETS_STAGING_DIR="${DIR}/sdk/kms/.tmp"

# Set build tags
BUILD_TAGS="${BUILD_TAGS:-"boundary"}"

# If its dev mode, only build for ourself
if [ "${BOUNDARY_DEV_BUILD}x" != "x" ] && [ "${XC_OSARCH}x" == "x" ]; then
    XC_OS=$(go env GOOS)
    XC_ARCH=$(go env GOARCH)
    XC_OSARCH=$(go env GOOS)/$(go env GOARCH)
elif [ "${XC_OSARCH}x" != "x" ]; then
    IFS='/' read -ra SPLITXC <<< "${XC_OSARCH}"
	DEV_PLATFORM="./pkg/${SPLITXC[0]}_${SPLITXC[1]}"
fi

# Determine the arch/os combos we're building for
XC_ARCH=${XC_ARCH:-"386 amd64"}
XC_OS=${XC_OS:-linux darwin windows freebsd openbsd netbsd solaris}
XC_OSARCH=${XC_OSARCH:-"linux/386 linux/amd64 linux/arm linux/arm64 darwin/386 darwin/amd64 windows/386 windows/amd64 freebsd/386 freebsd/amd64 freebsd/arm openbsd/386 openbsd/amd64 openbsd/arm netbsd/386 netbsd/amd64 solaris/amd64"}

GOPATH=${GOPATH:-$(go env GOPATH)}
case $(uname) in
    CYGWIN*)
        GOPATH="$(cygpath $GOPATH)"
        ;;
esac

# Delete the old dir
echo "==> Removing old assets directory..."
rm -f "${ASSETS_DIR}/*" "${ASSETS_STAGING_DIR}/*"
mkdir -p "${ASSETS_DIR}/" "${ASSETS_STAGING_DIR}/"

# Build!
# If GOX_PARALLEL_BUILDS is set, it will be used to add a "-parallel=${GOX_PARALLEL_BUILDS}" gox parameter
for CURR_PLUGIN in "$(ls $PLUGINS_DIR)"
  do
    cd "${PLUGINS_DIR}/${CURR_PLUGIN}"
    echo "==> Building ${CURR_PLUGIN} KMS plugin..."
    gox \
        -osarch="${XC_OSARCH}" \
        -gcflags "${GCFLAGS}" \
        -output "${ASSETS_STAGING_DIR}/{{.OS}}_{{.Arch}}/gkw-${CURR_PLUGIN}" \
        ${GOX_PARALLEL_BUILDS+-parallel="${GOX_PARALLEL_BUILDS}"} \
        -tags="${BUILD_TAGS}"
done
exit

# Move all the compiled things to the $GOPATH/bin
OLDIFS=$IFS
IFS=: MAIN_GOPATH=($GOPATH)
IFS=$OLDIFS

# Copy our OS/Arch to the bin/ directory
DEV_PLATFORM=${DEV_PLATFORM:-"./pkg/$(go env GOOS)_$(go env GOARCH)"}
for F in $(find ${DEV_PLATFORM} -mindepth 1 -maxdepth 1 -type f); do
    cp -f ${F} bin/
    cp -f ${F} ${MAIN_GOPATH}/bin/
done

if [ "${BOUNDARY_DEV_BUILD}x" = "x" ]; then
    # Zip and copy to the dist dir
    echo "==> Packaging..."
    for PLATFORM in $(find ./pkg -mindepth 1 -maxdepth 1 -type d); do
        OSARCH=$(basename ${PLATFORM})
        echo "--> ${OSARCH}"

        pushd $PLATFORM >/dev/null 2>&1
        zip ../${OSARCH}.zip ./*
        popd >/dev/null 2>&1
    done
fi

# Done!
echo
echo "==> Results:"
ls -hl bin/
