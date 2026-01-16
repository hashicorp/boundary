// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
)

func Test_ManagedGroups_RepoValidate(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	assert := assert.New(t)
	const op = "test"
	mg := AllocManagedGroup()
	t.Run("empty auth method", func(t *testing.T) {
		assert.Contains(mg.validate(ctx, op).Error(), errors.New(ctx, errors.InvalidParameter, op, "missing auth method id").Error(), errors.WithoutEvent())
	})
	t.Run("empty filter", func(t *testing.T) {
		mg.AuthMethodId = "amoidc_1234567890"
		assert.Contains(mg.validate(ctx, op).Error(), errors.New(ctx, errors.InvalidParameter, op, "missing filter").Error(), errors.WithoutEvent())
	})
	t.Run("bad filter", func(t *testing.T) {
		mg.AuthMethodId = "amoidc_1234567890"
		mg.Filter = "foobar"
		assert.Contains(mg.validate(ctx, op).Error(), errors.New(ctx, errors.InvalidParameter, op, "error evaluating filter expression").Error(), errors.WithoutEvent())
	})
	t.Run("valid", func(t *testing.T) {
		mg.AuthMethodId = "amoidc_1234567890"
		mg.Filter = TestFakeManagedGroupFilter
		assert.NoError(mg.validate(ctx, op))
	})
}
