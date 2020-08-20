package authmethods_test

import (
	"errors"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/kr/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticate(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	methods := authmethods.NewAuthMethodsClient(client)

	tok, apiErr, err := methods.Authenticate(tc.Context(), amId, "user", "passpass")
	require.NoError(err)
	assert.NoError(apiErr, pretty.Sprint(apiErr))
	assert.NotNil(tok)

	_, apiErr, err = methods.Authenticate(tc.Context(), amId, "user", "wrong")
	require.NoError(err)
	require.Error(apiErr)
	assert.Truef(errors.Is(apiErr, api.ErrUnauthorized), apiErr.Error())
}
