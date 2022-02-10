#!/usr/bin/env bash
#
# This script builds the required plugins.
set -e

ORIG_PATH=$(pwd);
echo "==> Building Host Plugins..."
for PLUGIN_TYPE in host; do
    rm -f $ORIG_PATH/plugins/$PLUGIN_TYPE/assets/boundary-plugin-${PLUGIN_TYPE}*
    for CURR_PLUGIN in $(ls $ORIG_PATH/plugins/$PLUGIN_TYPE/mains); do
        cd $ORIG_PATH/plugins/$PLUGIN_TYPE/mains/$CURR_PLUGIN;
        go build -v -o $ORIG_PATH/plugins/$PLUGIN_TYPE/assets/boundary-plugin-${PLUGIN_TYPE}-${CURR_PLUGIN} .;
        cd $ORIG_PATH;
    done;
    cd $ORIG_PATH/plugins/$PLUGIN_TYPE/assets;
    for CURR_PLUGIN in $(ls boundary-plugin*); do
        gzip -f -9 $CURR_PLUGIN;
    done;
    cd $ORIG_PATH;
done;
