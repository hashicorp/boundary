// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_DataKeyVersionDestructionJobRunAllowedTableName(t *testing.T) {
	allowedTableName1 := allocDataKeyVersionDestructionJobRunAllowedTableName()
	allowedTableName1.DataKeyVersionDestructionJobRunAllowedTableName.TableName = "abcd"
	allowedTableName2 := allowedTableName1.Clone()
	assert.Empty(t, cmp.Diff(allowedTableName1, allowedTableName2, protocmp.Transform()))
	allowedTableName1.DataKeyVersionDestructionJobRunAllowedTableName.TableName = "efgh"
	assert.NotEmpty(t, cmp.Diff(allowedTableName1, allowedTableName2, protocmp.Transform()))
}
