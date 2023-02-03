// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_DataKeyVersionDestructionJobProgress(t *testing.T) {
	progress1 := allocDataKeyVersionDestructionJobProgress()
	progress1.KeyId = "abcd"
	progress2 := progress1.Clone()
	assert.Empty(t, cmp.Diff(progress1, progress2, protocmp.Transform()))
	progress1.KeyId = "efgh"
	assert.NotEmpty(t, cmp.Diff(progress1, progress2, protocmp.Transform()))
}
