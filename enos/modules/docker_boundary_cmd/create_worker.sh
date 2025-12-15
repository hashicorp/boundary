#!/usr/bin/env sh
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

set -eu -o pipefail

boundary workers create worker-led \
  -worker-generated-auth-token $WORKER_TOKEN \
  -token env://BOUNDARY_TOKEN \
  -format json
