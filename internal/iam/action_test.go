// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"testing"

	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/stretchr/testify/assert"
)

// Test_CrudActions provides unit tests for CrudActions()
func Test_CrudActions(t *testing.T) {
	t.Parallel()
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		a := CrudlActions()
		assert.Equal(a[action.Create.String()], action.Create)
		assert.Equal(a[action.Update.String()], action.Update)
		assert.Equal(a[action.Read.String()], action.Read)
		assert.Equal(a[action.Delete.String()], action.Delete)
	})
	t.Run("invalid", func(t *testing.T) {
		assert := assert.New(t)
		a := CrudlActions()
		aType, ok := a["invalid"]
		assert.Equal(ok, false)
		assert.Equal(aType, action.Unknown)
	})
}

// Test_CrudlActions provides unit tests for CrudlActions()
func Test_CrudlActions(t *testing.T) {
	t.Parallel()
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		a := CrudlActions()
		assert.Equal(a[action.List.String()], action.List)
		assert.Equal(a[action.Create.String()], action.Create)
		assert.Equal(a[action.Update.String()], action.Update)
		assert.Equal(a[action.Read.String()], action.Read)
		assert.Equal(a[action.Delete.String()], action.Delete)
	})
	t.Run("invalid", func(t *testing.T) {
		assert := assert.New(t)
		a := CrudlActions()
		aType, ok := a["invalid"]
		assert.Equal(ok, false)
		assert.Equal(aType, action.Unknown)
	})
}
