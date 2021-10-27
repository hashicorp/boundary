package authmethods_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers/controller"
	tests_api "github.com/hashicorp/boundary/internal/tests/api"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthenticate tests the api calls and the audit events it should produce
func TestAuthenticate(t *testing.T) {
	// this cannot run in parallel because it relies on envvar
	// globals.BOUNDARY_DEVELOPER_ENABLE_EVENTS
	event.TestEnableEventing(t, true)

	assert, require := assert.New(t), require.New(t)
	eventConfig := event.TestEventerConfig(t, "TestAuthenticateAuditEntry", event.TestWithAuditSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(event.InitSysEventer(testLogger, testLock, "TestAuthenticateAuditEntry", event.WithEventerConfig(&eventConfig.EventerConfig)))
	tcConfig, err := config.DevController()
	require.NoError(err)
	tcConfig.Eventing = &eventConfig.EventerConfig

	tc := controller.NewTestController(t, &controller.TestControllerOpts{Config: tcConfig})
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

	require.NotNil(eventConfig.AuditEvents)
	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls

	tok, err = methods.Authenticate(tc.Context(), tc.Server().DevPasswordAuthMethodId, "login", map[string]interface{}{"login_name": "user", "password": "passpass"})
	require.NoError(err)
	assert.NotNil(tok)
	got := tests_api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())

	reqDetails := tests_api.GetEventDetails(t, got, "request")
	tests_api.AssertRedactedValues(t, reqDetails)
	tests_api.AssertRedactedValues(t, reqDetails["attributes"], "password")

	respDetails := tests_api.GetEventDetails(t, got, "response")
	tests_api.AssertRedactedValues(t, respDetails)
	tests_api.AssertRedactedValues(t, respDetails["attributes"], "token")

	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
	tok, err = methods.Authenticate(tc.Context(), tc.Server().DevPasswordAuthMethodId, "login", map[string]interface{}{"login_name": "user", "password": "bad-pass"})
	require.Error(err)
	assert.Nil(tok)
	got = tests_api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())

	reqDetails = tests_api.GetEventDetails(t, got, "request")
	tests_api.AssertRedactedValues(t, reqDetails)
	tests_api.AssertRedactedValues(t, reqDetails["attributes"], "password")
}
