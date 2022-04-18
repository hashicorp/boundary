#!/usr/bin/env bash
#
# This script builds the required plugins.
set -e

BINARY_SUFFIX=""
if [ "${GOOS}x" = "windowsx" ]; then
    BINARY_SUFFIX=".exe"
fi

# Get the parent directory of where this script is.
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
export DIR="$( cd -P "$( dirname "$SOURCE" )/.." && pwd )"

for PLUGIN_TYPE in {"kms","host"}; do
    echo "==> Building ${PLUGIN_TYPE} plugins..."
    rm -f $DIR/plugins/$PLUGIN_TYPE/assets/boundary-plugin-${PLUGIN_TYPE}*
    for CURR_PLUGIN in $(ls $DIR/plugins/$PLUGIN_TYPE/mains); do
        cd $DIR/plugins/$PLUGIN_TYPE/mains/$CURR_PLUGIN;
        go build -v -o $DIR/plugins/$PLUGIN_TYPE/assets/boundary-plugin-${PLUGIN_TYPE}-${CURR_PLUGIN}${BINARY_SUFFIX} .;
        cd $DIR;
    done;
    cd $DIR/plugins/$PLUGIN_TYPE/assets;
    for CURR_PLUGIN in $(ls boundary-plugin*); do
        gzip -f -9 $CURR_PLUGIN;
    done;
    cd $DIR;
done;