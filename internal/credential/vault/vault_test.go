package vault

import (
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
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t)
	require.NotNil(v)
	secret := v.CreateToken(t)
	require.NotNil(secret)

	token, err := secret.TokenID()
	require.NoError(err)
	assert.NotEmpty(token)
	require.Equal(token, secret.Auth.ClientToken)
	secretLookup := v.LookupToken(t, token)
	t.Log(testLogVaultSecret(t, secretLookup))

	conf := &clientConfig{
		Addr:       v.Addr,
		CaCert:     v.CaCert,
		ClientCert: v.ClientCert,
		ClientKey:  v.ClientKey,
		Token:      token,
	}

	// need to sleep so the expiration times will be different
	time.Sleep(100 * time.Millisecond)

	client, err := newClient(conf)
	require.NoError(err)
	require.NotNil(client)
	require.NoError(client.ping())

	renewedToken, err := client.renewToken()
	require.NoError(err)
	require.NotNil(renewedToken)
	renewedLookup := v.LookupToken(t, token)
	t.Log(testLogVaultSecret(t, renewedLookup))

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
	require.NotNil(v)
	secret := v.CreateToken(t)
	require.NotNil(secret)

	token, err := secret.TokenID()
	require.NoError(err)
	assert.NotEmpty(token)
	require.Equal(token, secret.Auth.ClientToken)
	secretLookup := v.LookupToken(t, token)
	t.Log(testLogVaultSecret(t, secretLookup))

	conf := &clientConfig{
		Addr:       v.Addr,
		CaCert:     v.CaCert,
		ClientCert: v.ClientCert,
		ClientKey:  v.ClientKey,
		Token:      token,
	}

	client, err := newClient(conf)
	require.NoError(err)
	require.NotNil(client)
	require.NoError(client.ping())

	tokenLookup, err := client.lookupToken()
	require.NoError(err)
	require.NotNil(tokenLookup)

	t.Log(testLogVaultSecret(t, tokenLookup))

	t1, t2 := tokenExpirationTime(t, secretLookup), tokenExpirationTime(t, tokenLookup)
	assert.True(t1.Equal(t2))
}

func TestClient_RevokeToken(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t)
	require.NotNil(v)
	secret := v.CreateToken(t)
	require.NotNil(secret)

	token, err := secret.TokenID()
	require.NoError(err)
	assert.NotEmpty(token)
	require.Equal(token, secret.Auth.ClientToken)
	secretLookup := v.LookupToken(t, token)
	t.Log(testLogVaultSecret(t, secretLookup))

	conf := &clientConfig{
		Addr:       v.Addr,
		CaCert:     v.CaCert,
		ClientCert: v.ClientCert,
		ClientKey:  v.ClientKey,
		Token:      token,
	}

	client, err := newClient(conf)
	require.NoError(err)
	require.NotNil(client)
	require.NoError(client.ping())

	tokenLookup, err := client.lookupToken()
	require.NoError(err)
	require.NotNil(tokenLookup)

	t.Log(testLogVaultSecret(t, tokenLookup))

	t1, t2 := tokenExpirationTime(t, secretLookup), tokenExpirationTime(t, tokenLookup)
	assert.True(t1.Equal(t2))

	err = client.revokeToken()
	require.NoError(err)

	// An attempt to lookup should now fail with a 403
	tokenLookup, err = client.lookupToken()
	require.Error(err)

	var respErr *vault.ResponseError
	ok := errors.As(err, &respErr)
	require.True(ok)
	assert.Equal(http.StatusForbidden, respErr.StatusCode)
}

func TestClient_Get(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)

	conf := &clientConfig{
		Addr:       v.Addr,
		CaCert:     v.CaCert,
		ClientCert: v.ClientCert,
		ClientKey:  v.ClientKey,
		Token:      v.RootToken,
	}

	client, err := newClient(conf)
	require.NoError(err)
	require.NotNil(client)
	require.NoError(client.ping())

	credPath := path.Join("database", "creds", "opened")
	cred, err := client.get(credPath)
	assert.NoError(err)
	assert.NotNil(cred)
}

func TestClient_Post(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t)
	v.MountPKI(t)

	conf := &clientConfig{
		Addr:       v.Addr,
		CaCert:     v.CaCert,
		ClientCert: v.ClientCert,
		ClientKey:  v.ClientKey,
		Token:      v.RootToken,
	}

	client, err := newClient(conf)
	require.NoError(err)
	require.NotNil(client)
	require.NoError(client.ping())

	credPath := path.Join("pki", "issue", "boundary")
	t.Run("post-body", func(t *testing.T) {
		credData := []byte(`{"common_name":"boundary.com"}`)
		cred, err := client.post(credPath, credData)
		assert.NoError(err)
		assert.NotNil(cred)
	})
	t.Run("nil-body", func(t *testing.T) {
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

	conf := &clientConfig{
		Addr:       v.Addr,
		CaCert:     v.CaCert,
		ClientCert: v.ClientCert,
		ClientKey:  v.ClientKey,
		Token:      v.RootToken,
	}

	client, err := newClient(conf)
	require.NoError(err)
	require.NotNil(client)
	assert.NoError(client.ping())

	// Create secret
	credPath := path.Join("database", "creds", "opened")
	cred, err := client.get(credPath)
	require.NoError(err)

	leaseLookup := v.LookupLease(t, cred.LeaseID)
	require.NotNil(leaseLookup)
	require.NotNil(leaseLookup.Data)

	// Verify lease has not been renewed
	require.Empty(leaseLookup.Data["last_renewal"])

	renewedLease, err := client.renewLease(cred.LeaseID, time.Hour)
	require.NoError(err)
	require.NotNil(renewedLease)
	assert.Equal(cred.LeaseID, renewedLease.LeaseID)
	assert.Equal(int(time.Hour.Seconds()), renewedLease.LeaseDuration)

	leaseLookup = v.LookupLease(t, cred.LeaseID)
	require.NotNil(leaseLookup)
	require.NotNil(leaseLookup.Data)

	// Verify lease been renewed
	require.NotEmpty(leaseLookup.Data["last_renewal"])
}
