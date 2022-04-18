package authmethods_test

import (
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers/controller"
	tests_api "github.com/hashicorp/boundary/internal/tests/api"
	capoidc "github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const global = "global"

func TestCrud(t *testing.T) {
	// this cannot run in parallel because it relies on envvar
	// globals.BOUNDARY_DEVELOPER_ENABLE_EVENTS
	event.TestEnableEventing(t, true)

	assert, require := assert.New(t), require.New(t)
	eventConfig := event.TestEventerConfig(t, "TestCrud", event.TestWithAuditSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(event.InitSysEventer(testLogger, testLock, "TestCrud", event.WithEventerConfig(&eventConfig.EventerConfig)))
	tcConfig, err := config.DevController()
	require.NoError(err)
	tcConfig.Eventing = &eventConfig.EventerConfig

	tc := controller.NewTestController(t, &controller.TestControllerOpts{Config: tcConfig})
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amClient := authmethods.NewClient(client)

	checkAuthMethod := func(step string, u *authmethods.AuthMethod, wantedName string, wantedVersion uint32) {
		require.NotNil(u, "returned no resource", step)
		gotName := ""
		if u.Name != "" {
			gotName = u.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.EqualValues(wantedVersion, u.Version)
	}

	require.NotNil(eventConfig.AuditEvents)
	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
	u, err := amClient.Create(tc.Context(), "password", global,
		authmethods.WithName("bar"))
	require.NoError(err)
	checkAuthMethod("create", u.Item, "bar", 1)

	got := tests_api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())
	reqItem := tests_api.GetEventDetails(t, got, "request")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, reqItem)

	respItem := tests_api.GetEventDetails(t, got, "response")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, respItem)
	tests_api.AssertRedactedValues(t, respItem["attributes"])

	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
	u, err = amClient.Read(tc.Context(), u.Item.Id)
	require.NoError(err)
	checkAuthMethod("read", u.Item, "bar", 1)

	got = tests_api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())
	tests_api.AssertRedactedValues(t, tests_api.GetEventDetails(t, got, "request"))

	respItem = tests_api.GetEventDetails(t, got, "response")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, respItem)
	tests_api.AssertRedactedValues(t, respItem["attributes"])

	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
	u, err = amClient.Update(tc.Context(), u.Item.Id, u.Item.Version, authmethods.WithName("buz"))
	require.NoError(err)
	checkAuthMethod("update", u.Item, "buz", 2)
	got = tests_api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())

	tests_api.AssertRedactedValues(t, tests_api.GetEventDetails(t, got, "request")["item"].(map[string]interface{}))

	respItem = tests_api.GetEventDetails(t, got, "response")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, respItem)
	tests_api.AssertRedactedValues(t, respItem["attributes"])

	u, err = amClient.Update(tc.Context(), u.Item.Id, u.Item.Version, authmethods.DefaultName())
	require.NoError(err)
	checkAuthMethod("update", u.Item, "", 3)

	_, err = amClient.Delete(tc.Context(), u.Item.Id)
	require.NoError(err)

	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
	// OIDC auth methods
	u, err = amClient.Create(tc.Context(), "oidc", global,
		authmethods.WithName("foo"),
		authmethods.WithOidcAuthMethodApiUrlPrefix("https://api.com"),
		authmethods.WithOidcAuthMethodIssuer("https://example.com"),
		authmethods.WithOidcAuthMethodClientSecret("secret"),
		authmethods.WithOidcAuthMethodClientId("client-id"))
	require.NoError(err)
	checkAuthMethod("create", u.Item, "foo", 1)
	got = tests_api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())

	reqItem = tests_api.GetEventDetails(t, got, "request")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, reqItem)
	tests_api.AssertRedactedValues(t, reqItem["attributes"], "client_secret")

	respItem = tests_api.GetEventDetails(t, got, "response")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, respItem)
	tests_api.AssertRedactedValues(t, respItem["attributes"])

	u, err = amClient.Read(tc.Context(), u.Item.Id)
	require.NoError(err)
	checkAuthMethod("read", u.Item, "foo", 1)

	u, err = amClient.Update(tc.Context(), u.Item.Id, u.Item.Version, authmethods.WithName("bar"))
	require.NoError(err)
	checkAuthMethod("update", u.Item, "bar", 2)

	u, err = amClient.Update(tc.Context(), u.Item.Id, u.Item.Version, authmethods.DefaultName())
	require.NoError(err)
	checkAuthMethod("update", u.Item, "", 3)

	_, err = amClient.Delete(tc.Context(), u.Item.Id)
	require.NoError(err)
}

func TestCustomMethods(t *testing.T) {
	// this cannot run in parallel because it relies on envvar
	// globals.BOUNDARY_DEVELOPER_ENABLE_EVENTS
	event.TestEnableEventing(t, true)

	assert, require := assert.New(t), require.New(t)
	eventConfig := event.TestEventerConfig(t, "TestCrud", event.TestWithAuditSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(event.InitSysEventer(testLogger, testLock, "TestCrud", event.WithEventerConfig(&eventConfig.EventerConfig)))
	tcConfig, err := config.DevController()
	require.NoError(err)
	tcConfig.Eventing = &eventConfig.EventerConfig

	tc := controller.NewTestController(t, &controller.TestControllerOpts{Config: tcConfig})
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)

	amClient := authmethods.NewClient(client)

	tp := capoidc.StartTestProvider(t)
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)

	u, err := amClient.Create(tc.Context(), "oidc", global,
		authmethods.WithName("foo"),
		authmethods.WithOidcAuthMethodIssuer(tp.Addr()),
		authmethods.WithOidcAuthMethodApiUrlPrefix("https://example.com"),
		authmethods.WithOidcAuthMethodClientSecret("secret"),
		authmethods.WithOidcAuthMethodClientId("client-id"),
		authmethods.WithOidcAuthMethodSigningAlgorithms([]string{string("EdDSA")}),
		authmethods.WithOidcAuthMethodIdpCaCerts([]string{tp.CACert()}))
	require.NoError(err)

	const newState = "active-private"
	nilU, err := amClient.ChangeState(tc.Context(), u.Item.Id, u.Item.Version, newState)
	require.Error(err)
	assert.Nil(nilU)

	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
	u, err = amClient.ChangeState(tc.Context(), u.Item.Id, u.Item.Version, newState, authmethods.WithOidcAuthMethodDisableDiscoveredConfigValidation(true))
	require.NoError(err)
	assert.NotNil(u)
	assert.Equal(newState, u.Item.Attributes["state"])
	got := tests_api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())

	reqDetails := tests_api.GetEventDetails(t, got, "request")
	tests_api.AssertRedactedValues(t, reqDetails)
	tests_api.AssertRedactedValues(t, reqDetails["attributes"])

	respItem := tests_api.GetEventDetails(t, got, "response")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, respItem)
	tests_api.AssertRedactedValues(t, respItem["attributes"])

	_, err = amClient.ChangeState(tc.Context(), u.Item.Id, u.Item.Version, "", authmethods.WithOidcAuthMethodDisableDiscoveredConfigValidation(true))
	assert.Error(err)
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amClient := authmethods.NewClient(client)

	u, err := amClient.Create(tc.Context(), "password", global,
		authmethods.WithName("foo"))
	require.NoError(err)
	assert.NotNil(u)

	// Updating the wrong version should fail.
	_, err = amClient.Update(tc.Context(), u.Item.Id, 73, authmethods.WithName("anything"))
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// Create another resource with the same name.
	_, err = amClient.Create(tc.Context(), "password", global,
		authmethods.WithName("foo"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)

	// TODO: Confirm that we can't create an oidc auth method with the same name.

	_, err = amClient.Read(tc.Context(), password.AuthMethodPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = amClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())

	_, err = amClient.Update(tc.Context(), u.Item.Id, u.Item.Version)
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
