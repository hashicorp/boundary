#!/usr/bin/env sh
# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1

set -eu -o pipefail

boundary authenticate password \
  -login-name $LOGIN_NAME \
  -password env://BPASS \
  -format json
