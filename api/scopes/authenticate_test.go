package scopes_test

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/stretchr/testify/assert"
)

func TestAuthenticate(t *testing.T) {
	assert := assert.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	org := &scopes.Organization{
		Client: client,
	}
	ctx := context.Background()

	apiErr, err := org.Authenticate(ctx, "anything", "admin", "hunter2")
	assert.NoError(err)
	assert.Nil(apiErr)
}
