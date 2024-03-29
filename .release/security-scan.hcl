# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

container {
	dependencies = true
	alpine_secdb = true
	secrets      = false
}

binary {
	secrets      = true
	go_modules   = true
	osv          = true
	oss_index    = true
	nvd          = true
}
