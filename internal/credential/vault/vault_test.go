package vault

import (
	"testing"
	"time"

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
	assert, require := assert.New(t), require.New(t)
	v, cleanup := NewTestVaultServer(t, TestNoTLS)
	defer cleanup()
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
	require.NoError(client.Ping())

	renewedToken, err := client.RenewToken()
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
	assert, require := assert.New(t), require.New(t)
	v, cleanup := NewTestVaultServer(t, TestNoTLS)
	defer cleanup()
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
	require.NoError(client.Ping())

	tokenLookup, err := client.LookupToken()
	require.NoError(err)
	require.NotNil(tokenLookup)

	t.Log(testLogVaultSecret(t, tokenLookup))

	t1, t2 := tokenExpirationTime(t, secretLookup), tokenExpirationTime(t, tokenLookup)
	assert.True(t1.Equal(t2))
}
