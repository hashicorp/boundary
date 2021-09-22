package authmethods_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
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

	tok, err := methods.Authenticate(tc.Context(), tc.Server().DevPasswordAuthMethodId, "login", map[string]interface{}{"login_name": "user", "password": "passpass"})
	require.NoError(err)
	assert.NotNil(tok)

	_, err = methods.Authenticate(tc.Context(), tc.Server().DevPasswordAuthMethodId, "login", map[string]interface{}{"login_name": "user", "password": "wrong"})
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValuesf(http.StatusUnauthorized, apiErr.Response().StatusCode(), "Expected unauthorized, got %q", apiErr.Message)

	// Also ensure that, for now, using "credentials" still works, as well as no command.
	reqBody := map[string]interface{}{
		"attributes": map[string]interface{}{"login_name": "user", "password": "passpass"},
	}
	req, err := client.NewRequest(tc.Context(), "POST", fmt.Sprintf("auth-methods/%s:authenticate", tc.Server().DevPasswordAuthMethodId), reqBody)
	require.NoError(err)
	resp, err := client.Do(req)
	require.NoError(err)

	result := new(authmethods.AuthenticateResult)
	apiErr, err = resp.Decode(result)
	require.NoError(err)
	require.Nil(apiErr)

	token := new(authtokens.AuthToken)
	require.NoError(json.Unmarshal(result.GetRawAttributes(), token))
	require.NotEmpty(token.Token)
}
