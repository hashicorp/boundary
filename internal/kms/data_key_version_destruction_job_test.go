// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_DataKeyVersionDestructionJob(t *testing.T) {
	job1 := allocDataKeyVersionDestructionJob()
	job1.KeyId = "abcd"
	job2 := job1.Clone()
	assert.Empty(t, cmp.Diff(job1, job2, protocmp.Transform()))
	job1.KeyId = "efgh"
	assert.NotEmpty(t, cmp.Diff(job1, job2, protocmp.Transform()))
}
