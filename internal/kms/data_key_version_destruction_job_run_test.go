// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_DataKeyVersionDestructionJobRun(t *testing.T) {
	run1 := allocDataKeyVersionDestructionJobRun()
	run1.KeyId = "abcd"
	run2 := run1.Clone()
	assert.Empty(t, cmp.Diff(run1, run2, protocmp.Transform()))
	run1.KeyId = "efgh"
	assert.NotEmpty(t, cmp.Diff(run1, run2, protocmp.Transform()))
}
