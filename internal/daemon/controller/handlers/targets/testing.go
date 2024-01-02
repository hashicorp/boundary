// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package targets

import (
	"testing"
)

// SetupSuiteTargetFilters is used to ensure that OSS tests run from the ENT repo use the OSS level of target filtering
func SetupSuiteTargetFilters(t *testing.T) {
	oldFn := AuthorizeSessionWorkerFilterFn
	AuthorizeSessionWorkerFilterFn = AuthorizeSessionWithWorkerFilter

	t.Cleanup(func() {
		AuthorizeSessionWorkerFilterFn = oldFn
	})
}
