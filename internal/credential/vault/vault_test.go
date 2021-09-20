package vault

import (
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newClient(t *testing.T) {
	t.Parallel()
	t.Run("nilConfig", func(t *testing.T) {
		assert := assert.New(t)
		var c *clientConfig
		client, err := newClient(c)
		assert.Error(err)
		assert.Nil(client)
	})
}

func TestClient_RenewToken(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	v := NewTestVaultServer(t)

	_, token := v.CreateToken(t)
	secretLookup := v.LookupToken(t, token)

	// need to sleep so the expiration times will be different
	time.Sleep(100 * time.Millisecond)

	client := v.clientUsingToken(t, token)
	renewedToken, err := client.renewToken()
	require.NoError(t, err)
	assert.NotNil(renewedToken)

	renewedLookup := v.LookupToken(t, token)
	t1, t2 := tokenExpirationTime(t, secretLookup), tokenExpirationTime(t, renewedLookup)
	assert.False(t1.Equal(t2))
	assert.True(t2.After(t1))
}

func tokenExpirationTime(t *testing.T, s *vault.Secret) time.Time {
	t.Helper()
	require := require.New(t)

	require.NotNil(s)
	d1 := s.Data
	require.NotNil(d1)
	exp := d1["expire_time"]
	require.NotEmpty(exp)
	et, err := time.Parse(time.RFC3339, exp.(string))
	require.NoError(err)
	return et
}

func TestClient_LookupToken(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t)

	_, token := v.CreateToken(t)
	secretLookup := v.LookupToken(t, token)

	client := v.clientUsingToken(t, token)
	tokenLookup, err := client.lookupToken()
	assert.NoError(err)
	require.NotNil(tokenLookup)

	t1, t2 := tokenExpirationTime(t, secretLookup), tokenExpirationTime(t, tokenLookup)
	assert.True(t1.Equal(t2))
}

func TestClient_RevokeToken(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t)

	_, token := v.CreateToken(t)

	client := v.clientUsingToken(t, token)
	tokenLookup, err := client.lookupToken()
	assert.NoError(err)
	assert.NotNil(tokenLookup)

	require.NoError(client.revokeToken())

	// An attempt to lookup should now fail with a 403
	tokenLookup, err = client.lookupToken()
	require.Error(err)
	assert.Nil(tokenLookup)

	var respErr *vault.ResponseError
	ok := errors.As(err, &respErr)
	require.True(ok)
	assert.Equal(http.StatusForbidden, respErr.StatusCode)
}

func TestClient_Get(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)

	client := v.client(t)

	cred, err := client.get(path.Join("database", "creds", "opened"))
	assert.NoError(err)
	assert.NotNil(cred)
}

func TestClient_Post(t *testing.T) {
	t.Parallel()
	v := NewTestVaultServer(t, WithTestVaultTLS(TestServerTLS))
	v.MountPKI(t)
	client := v.client(t)
	credPath := path.Join("pki", "issue", "boundary")
	t.Run("post-body", func(t *testing.T) {
		assert := assert.New(t)
		credData := []byte(`{"common_name":"boundary.com"}`)
		cred, err := client.post(credPath, credData)
		assert.NoError(err)
		assert.NotNil(cred)
	})
	t.Run("nil-body", func(t *testing.T) {
		assert := assert.New(t)
		cred, err := client.post(credPath, nil)
		assert.Error(err)
		assert.Contains(err.Error(), "common_name field is required")
		assert.Nil(cred)
	})
}

func TestClient_RenewLease(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)

	_, token := v.CreateToken(t, WithPolicies([]string{"boundary-controller", "database"}))
	client := v.clientUsingToken(t, token)

	// Create secret
	cred, err := client.get(path.Join("database", "creds", "opened"))
	assert.NoError(err)
	require.NotNil(cred)

	leaseLookup := v.LookupLease(t, cred.LeaseID)
	require.NotNil(leaseLookup)
	require.NotNil(leaseLookup.Data)

	// Verify lease has not been renewed
	assert.Empty(leaseLookup.Data["last_renewal"])

	renewedLease, err := client.renewLease(cred.LeaseID, time.Hour)
	assert.NoError(err)
	require.NotNil(renewedLease)
	assert.Equal(cred.LeaseID, renewedLease.LeaseID)

	leaseLookup = v.LookupLease(t, cred.LeaseID)
	require.NotNil(leaseLookup)
	require.NotNil(leaseLookup.Data)

	// Verify lease been renewed
	assert.NotEmpty(leaseLookup.Data["last_renewal"])
}

func TestClient_capabilities(t *testing.T) {
	t.Parallel()
	v := NewTestVaultServer(t)

	tests := []struct {
		name        string
		polices     []string
		require     pathCapabilities
		wantMissing pathCapabilities
	}{
		{
			polices:     []string{"default"},
			require:     requiredCapabilities,
			wantMissing: pathCapabilities{"sys/leases/revoke": updateCapability},
		},
		{
			polices: []string{"default", "boundary-controller"},
			require: requiredCapabilities,
		},
		{
			polices: []string{"boundary-controller"},
			require: requiredCapabilities,
		},
	}
	for _, tt := range tests {
		tt := tt
		if tt.name == "" {
			tt.name = fmt.Sprintf("%v", tt.polices)
		}
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			_, token := v.CreateToken(t, WithPolicies(tt.polices))
			client := v.clientUsingToken(t, token)

			have, err := client.capabilities(tt.require.paths())
			assert.NoError(err)
			got := have.missing(tt.require)
			assert.Equalf(tt.wantMissing, got, "pathCapabilities: want: {%s} got: {%s}", tt.wantMissing, got)
		})
	}
}

func TestClient_revokeLease(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t, WithDockerNetwork(true), WithTestVaultTLS(TestClientTLS))
	testDatabase := v.MountDatabase(t)

	_, token := v.CreateToken(t, WithPolicies([]string{"boundary-controller", "database"}))
	client := v.clientUsingToken(t, token)

	cred, err := client.get(path.Join("database", "creds", "opened"))
	assert.NoError(err)
	require.NotNil(cred)

	// verify the database credentials work
	assert.NoError(testDatabase.ValidateCredential(t, cred))

	// revoke the database credentials
	assert.NoError(client.revokeLease(cred.LeaseID))

	// verify the database credentials no longer work
	assert.Error(testDatabase.ValidateCredential(t, cred))
}
