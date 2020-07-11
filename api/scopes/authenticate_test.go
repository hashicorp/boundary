package scopes_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticate(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Org{
		Client: client,
	}
	ctx := context.Background()

	tok, apiErr, err := org.Authenticate(ctx, "anything", "admin", "hunter2")
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.NotNil(tok)

	_, apiErr, err = org.Authenticate(ctx, "anything", "wrong", "wrong")
	assert.NoError(err)
	require.NotNil(t, apiErr)
	assert.EqualValuesf(http.StatusUnauthorized, *apiErr.Status, "Expected unauthenticated, got %q", *apiErr.Message)
}
