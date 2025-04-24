#!/usr/bin/env sh
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

set -eu -o pipefail

boundary workers create controller-led \
  -token env://BOUNDARY_TOKEN \
  -format json
