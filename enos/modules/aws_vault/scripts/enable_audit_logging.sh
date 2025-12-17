#!/bin/env sh
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

set -eux

$VAULT_BIN_PATH audit enable file file_path="$LOG_FILE_PATH"
