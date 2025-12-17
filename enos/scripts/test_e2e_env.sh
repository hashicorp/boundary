#!/bin/bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

DIR=$(pwd)

SCRIPTS_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
STATEDIR=$(ls -td $SCRIPTS_DIR/../.enos/*/ | head -1) # get latest directory

# Default to linux format
FORMAT="linux"

# Parse flag
while getopts "f:" opt; do
  case ${opt} in
    f)
      if [[ "$OPTARG" == "linux" || "$OPTARG" == "windows" ]]; then
        FORMAT="$OPTARG"
      else
        echo "Invalid format. Use 'linux' or 'windows'."
        exit 1
      fi
      ;;
    *)
      echo "Usage: $0 [-f linux|windows]"
      exit 1
      ;;
  esac
done

cd $STATEDIR

if [[ "$FORMAT" == "windows" ]]; then
  terraform show -json terraform.tfstate | jq -r '.values.root_module.child_modules[].resources[] | select(.address=="module.run_e2e_test.enos_local_exec.run_e2e_test") | .values.environment | to_entries[] | select(.value != "") | "$env:\(.key)=\(.value|@sh);"'
else
  terraform show -json terraform.tfstate | jq -r '.values.root_module.child_modules[].resources[] | select(.address=="module.run_e2e_test.enos_local_exec.run_e2e_test") | .values.environment | to_entries[] | select(.value != "") | "export \(.key)=\(.value|@sh);"'
fi

cd $DIR
