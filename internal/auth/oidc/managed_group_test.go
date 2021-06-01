package oidc

import (
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
)

func Test_ManagedGroups_RepoValidate(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	const op = "test"
	mg := AllocManagedGroup()
	t.Run("empty auth method", func(t *testing.T) {
		assert.Contains(mg.validate(op).Error(), errors.New(errors.InvalidParameter, op, "missing auth method id").Error())
	})
	t.Run("empty filter", func(t *testing.T) {
		mg.AuthMethodId = "amoidc_1234567890"
		assert.Contains(mg.validate(op).Error(), errors.New(errors.InvalidParameter, op, "missing filter").Error())
	})
	t.Run("bad filter", func(t *testing.T) {
		mg.AuthMethodId = "amoidc_1234567890"
		mg.Filter = "foobar"
		assert.Contains(mg.validate(op).Error(), errors.New(errors.InvalidParameter, op, "error evaluating filter expression").Error())
	})
	t.Run("valid", func(t *testing.T) {
		mg.AuthMethodId = "amoidc_1234567890"
		mg.Filter = testFakeFilter
		assert.NoError(mg.validate(op))
	})
}
