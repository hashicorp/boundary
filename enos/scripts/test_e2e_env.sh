#!/bin/bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

DIR=$(pwd)

SCRIPTS_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
STATEDIR=$(ls -td $SCRIPTS_DIR/../.enos/*/ | head -1) # get latest directory

cd $STATEDIR
terraform show -json terraform.tfstate | jq -r '.values.root_module.child_modules[].resources[] | select(.address=="module.run_e2e_test.enos_local_exec.run_e2e_test") | .values.environment | to_entries[] | "export \(.key)=\(.value|@sh)"'
terraform show -json terraform.tfstate | jq -r '.values.root_module.child_modules[].resources[] | select(.address=="module.run_e2e_ui_test.enos_local_exec.run_e2e_ui_test") | .values.environment | to_entries[] | "export \(.key)=\(.value|@sh)"'

cd $DIR
