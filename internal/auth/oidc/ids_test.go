package oidc

import (
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetup(t *testing.T) {
	docker.StartDbInDocker("postgres")
}

func Test_Ids(t *testing.T) {
	t.Parallel()
	t.Run(AuthMethodPrefix, func(t *testing.T) {
		id, err := newAuthMethodId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, AuthMethodPrefix+"_"))
	})
	t.Run(AccountPrefix, func(t *testing.T) {
		id, err := newAccountId("public-id", "test-issuer", "test-subject")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, AccountPrefix+"_"))
	})
}
