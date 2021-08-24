package oidc

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Ids(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	t.Run(AuthMethodPrefix, func(t *testing.T) {
		id, err := newAuthMethodId(ctx)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, AuthMethodPrefix+"_"))
	})
	t.Run(AccountPrefix, func(t *testing.T) {
		id, err := newAccountId(ctx, "public-id", "test-issuer", "test-subject")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, AccountPrefix+"_"))
	})
}
