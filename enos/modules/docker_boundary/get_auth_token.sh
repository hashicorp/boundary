#!/usr/bin/env sh
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

set -eu -o pipefail

boundary authenticate password \
  -login-name $LOGIN_NAME \
  -password env://BPASS \
  -format json
