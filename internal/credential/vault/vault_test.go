// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-uuid"
	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newClient(t *testing.T) {
	t.Parallel()
	v := NewTestVaultServer(t)

	corId, err := uuid.GenerateUUID()
	require.NoError(t, err)
	corCtx, err := event.NewCorrelationIdContext(context.Background(), corId)
	require.NoError(t, err)

	tests := []struct {
		name         string
		ctx          context.Context
		wantErr      bool
		wantCorId    string
		clientConfig *clientConfig
	}{
		{
			name:    "nil-config",
			ctx:     context.Background(),
			wantErr: true,
		},
		{
			name: "empty-addr",
			ctx:  context.Background(),
			clientConfig: &clientConfig{
				Token: TokenSecret(v.RootToken),
			},
			wantErr: true,
		},
		{
			name: "empty-token",
			ctx:  context.Background(),
			clientConfig: &clientConfig{
				Addr: v.Addr,
			},
			wantErr: true,
		},
		{
			name: "valid-config",
			ctx:  context.Background(),
			clientConfig: &clientConfig{
				Addr:  v.Addr,
				Token: TokenSecret(v.RootToken),
			},
			wantCorId: "",
		},
		{
			name: "valid-config-with-correlation-id",
			ctx:  corCtx,
			clientConfig: &clientConfig{
				Addr:  v.Addr,
				Token: TokenSecret(v.RootToken),
			},
			wantCorId: corId,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			client, err := newClient(tt.ctx, tt.clientConfig)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(client)
				return
			}
			require.NoError(err)
			assert.NotNil(client)

			headers, err := client.headers(context.Background())
			require.NoError(err)
			corIdHeader := headers.Get(globals.CorrelationIdKey)
			assert.Equal(tt.wantCorId, corIdHeader)
		})
	}
}

func TestClient_RenewToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert := assert.New(t)
	v := NewTestVaultServer(t)

	_, token := v.CreateToken(t)
	secretLookup := v.LookupToken(t, token)

	// need to sleep so the expiration times will be different
	time.Sleep(100 * time.Millisecond)

	client := v.ClientUsingToken(t, token)
	renewedToken, err := client.renewToken(ctx)
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
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t)

	_, token := v.CreateToken(t)
	secretLookup := v.LookupToken(t, token)

	client := v.ClientUsingToken(t, token)
	tokenLookup, err := client.lookupToken(ctx)
	assert.NoError(err)
	require.NotNil(tokenLookup)

	t1, t2 := tokenExpirationTime(t, secretLookup), tokenExpirationTime(t, tokenLookup)
	assert.True(t1.Equal(t2))
}

func TestClient_RevokeToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t)

	_, token := v.CreateToken(t)

	client := v.ClientUsingToken(t, token)
	tokenLookup, err := client.lookupToken(ctx)
	assert.NoError(err)
	assert.NotNil(tokenLookup)

	require.NoError(client.revokeToken(ctx))

	// An attempt to lookup should now fail with a 403
	tokenLookup, err = client.lookupToken(ctx)
	require.Error(err)
	assert.Nil(tokenLookup)

	var respErr *vault.ResponseError
	ok := errors.As(err, &respErr)
	require.True(ok)
	assert.Equal(http.StatusForbidden, respErr.StatusCode)
}

func TestClient_Get(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert := assert.New(t)
	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)

	client := v.client(t)

	cred, err := client.get(ctx, path.Join("database", "creds", "opened"))
	assert.NoError(err)
	assert.NotNil(cred)
}

func TestClient_Post(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := NewTestVaultServer(t, WithTestVaultTLS(TestServerTLS))
	v.MountPKI(t)
	client := v.client(t)
	credPath := path.Join("pki", "issue", "boundary")
	t.Run("post-body", func(t *testing.T) {
		assert := assert.New(t)
		credData := []byte(`{"common_name":"boundary.com"}`)
		cred, err := client.post(ctx, credPath, credData)
		assert.NoError(err)
		assert.NotNil(cred)
	})
	t.Run("nil-body", func(t *testing.T) {
		assert := assert.New(t)
		cred, err := client.post(ctx, credPath, nil)
		assert.Error(err)
		assert.Contains(err.Error(), "common_name field is required")
		assert.Nil(cred)
	})
}

func TestClient_RenewLease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)

	_, token := v.CreateToken(t, WithPolicies([]string{"boundary-controller", "database"}))
	client := v.ClientUsingToken(t, token)

	// Create secret
	cred, err := client.get(ctx, path.Join("database", "creds", "opened"))
	assert.NoError(err)
	require.NotNil(cred)

	leaseLookup := v.LookupLease(t, cred.LeaseID)
	require.NotNil(leaseLookup)
	require.NotNil(leaseLookup.Data)

	// Verify lease has not been renewed
	assert.Empty(leaseLookup.Data["last_renewal"])

	renewedLease, err := client.renewLease(ctx, cred.LeaseID, time.Hour)
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
	ctx := context.Background()
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
			client := v.ClientUsingToken(t, token)

			have, err := client.capabilities(ctx, tt.require.paths())
			assert.NoError(err)
			got := have.missing(tt.require)
			assert.Equalf(tt.wantMissing, got, "pathCapabilities: want: {%s} got: {%s}", tt.wantMissing, got)
		})
	}
}

func TestClient_revokeLease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t, WithDockerNetwork(true), WithTestVaultTLS(TestClientTLS))
	testDatabase := v.MountDatabase(t)

	_, token := v.CreateToken(t, WithPolicies([]string{"boundary-controller", "database"}))
	client := v.ClientUsingToken(t, token)

	cred, err := client.get(ctx, path.Join("database", "creds", "opened"))
	assert.NoError(err)
	require.NotNil(cred)

	// verify the database credentials work
	assert.NoError(testDatabase.ValidateCredential(t, cred))

	// revoke the database credentials
	assert.NoError(client.revokeLease(ctx, cred.LeaseID))

	// verify the database credentials no longer work
	assert.Error(testDatabase.ValidateCredential(t, cred))
}

func Test_headers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := NewTestVaultServer(t)

	clientConfig := &clientConfig{
		Addr:  v.Addr,
		Token: TokenSecret(v.RootToken),
	}

	client, err := newClient(ctx, clientConfig)
	require.NoError(t, err)
	assert.NotNil(t, client)

	// Add header to underlying vault client
	client.cl.AddHeader("test-header", "test-header-value")

	// Get headers from client
	headers, err := client.headers(context.Background())
	require.NoError(t, err)
	got := headers.Get("test-header")
	assert.Equal(t, "test-header-value", got)
}
