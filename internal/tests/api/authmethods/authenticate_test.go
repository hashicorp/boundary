package authmethods_test

import (
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticate(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	methods := authmethods.NewClient(client)

	tok, err := methods.Authenticate(tc.Context(), tc.Server().DevAuthMethodId, map[string]interface{}{"login_name": "user", "password": "passpass"})
	require.NoError(err)
	assert.NotNil(tok)

	_, err = methods.Authenticate(tc.Context(), tc.Server().DevAuthMethodId, map[string]interface{}{"login_name": "user", "password": "wrong"})
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValuesf(http.StatusUnauthorized, apiErr.Response().StatusCode(), "Expected unauthorized, got %q", apiErr.Message)
}
