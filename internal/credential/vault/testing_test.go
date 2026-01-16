// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestCredentialStores(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	count := 4
	css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), count)
	assert.Len(css, count)
	for _, cs := range css {
		assert.NotEmpty(cs.GetPublicId())
		assert.NotNil(cs.Token())
		assert.NotNil(cs.ClientCertificate())
	}
}

func Test_TestCredentialLibraries(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

	count := 4
	libs := TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), globals.UnspecifiedCredentialType, count)
	assert.Len(libs, count)
	for _, lib := range libs {
		assert.NotEmpty(lib.GetPublicId())
	}
}

func testLogVaultSecret(t *testing.T, v *vault.Secret) string {
	t.Helper()
	require := require.New(t)
	require.NotNil(v)
	b, err := json.MarshalIndent(v, "", "  ")
	require.NoError(err)
	require.NotEmpty(b)
	return string(b)
}

func TestTestVaultServer_CreateToken(t *testing.T) {
	t.Parallel()
	assertIsRenewable := func() func(t *testing.T, s *vault.Secret) {
		const op = "assertIsRenewable"
		return func(t *testing.T, s *vault.Secret) {
			isRenewable, err := s.TokenIsRenewable()
			assert.NoError(t, err, op)
			assert.True(t, isRenewable, op)
			assert.Equal(t, isRenewable, s.Auth.Renewable, op)
		}
	}

	assertIsNotRenewable := func() func(t *testing.T, s *vault.Secret) {
		const op = "assertIsNotRenewable"
		return func(t *testing.T, s *vault.Secret) {
			isRenewable, err := s.TokenIsRenewable()
			assert.NoError(t, err, op)
			assert.False(t, isRenewable, op)
			assert.Equal(t, isRenewable, s.Auth.Renewable, op)
		}
	}

	assertIsOrphan := func() func(t *testing.T, s *vault.Secret) {
		const op = "assertIsOrphan"
		return func(t *testing.T, s *vault.Secret) {
			assert.True(t, s.Auth.Orphan, op)
		}
	}

	assertIsNotOrphan := func() func(t *testing.T, s *vault.Secret) {
		const op = "assertIsNotOrphan"
		return func(t *testing.T, s *vault.Secret) {
			assert.False(t, s.Auth.Orphan, op)
		}
	}

	assertIsPeriodic := func() func(t *testing.T, s *vault.Secret) {
		const op = "assertIsPeriodic"
		return func(t *testing.T, s *vault.Secret) {
			_, ok := s.Data["period"]
			assert.True(t, ok, op)
		}
	}

	assertIsNotPeriodic := func() func(t *testing.T, s *vault.Secret) {
		const op = "assertIsNotPeriodic"
		return func(t *testing.T, s *vault.Secret) {
			_, ok := s.Data["period"]
			assert.False(t, ok, op)
		}
	}

	assertPeriod := func(want time.Duration) func(t *testing.T, s *vault.Secret) {
		const op = "assertPeriod"
		return func(t *testing.T, s *vault.Secret) {
			period, ok := s.Data["period"]
			if assert.True(t, ok, op) {
				require.NotNil(t, period)
				gotPeriod, err := parseutil.ParseDurationSecond(period)
				require.NoError(t, err)
				if assert.True(t, ok, op) {
					delta := 5 * time.Minute
					assert.InDelta(t, want.Seconds(), gotPeriod.Seconds(), delta.Seconds())
				}
			}
		}
	}

	assertDefaultPeriod := func() func(t *testing.T, s *vault.Secret) {
		defaultPeriod := 24 * time.Hour
		if deadline, ok := t.Deadline(); ok {
			defaultPeriod = time.Until(deadline)
		}
		return assertPeriod(defaultPeriod)
	}

	combine := func(fns ...func(*testing.T, *vault.Secret)) func(*testing.T, *vault.Secret) {
		return func(t *testing.T, s *vault.Secret) {
			for _, fn := range fns {
				fn(t, s)
			}
		}
	}

	tests := []struct {
		name        string
		opts        []TestOption
		tokenChkFn  func(t *testing.T, token *vault.Secret)
		lookupChkFn func(t *testing.T, lookup *vault.Secret)
	}{
		{
			name:        "DefaultOptions",
			tokenChkFn:  combine(assertIsRenewable(), assertIsOrphan()),
			lookupChkFn: combine(assertIsPeriodic(), assertDefaultPeriod()),
		},
		{
			name:        "NotPeriodic",
			opts:        []TestOption{TestPeriodicToken(false)},
			tokenChkFn:  combine(assertIsRenewable(), assertIsOrphan()),
			lookupChkFn: assertIsNotPeriodic(),
		},
		{
			name:        "NotOrphan",
			opts:        []TestOption{TestOrphanToken(false)},
			tokenChkFn:  combine(assertIsRenewable(), assertIsNotOrphan()),
			lookupChkFn: combine(assertIsPeriodic(), assertDefaultPeriod()),
		},
		{
			name:        "NotRenewable",
			opts:        []TestOption{TestRenewableToken(false)},
			tokenChkFn:  combine(assertIsNotRenewable(), assertIsOrphan()),
			lookupChkFn: combine(assertIsPeriodic(), assertDefaultPeriod()),
		},
		{
			name:        "TokenPeriod",
			opts:        []TestOption{WithTokenPeriod(3 * time.Hour)},
			tokenChkFn:  combine(assertIsRenewable(), assertIsOrphan()),
			lookupChkFn: combine(assertIsPeriodic(), assertPeriod(3*time.Hour)),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			v := NewTestVaultServer(t)
			require.NotNil(v)
			secret, token := v.CreateToken(t, tt.opts...)
			require.NotNil(secret)
			require.NotEmpty(token)
			require.Equal(token, secret.Auth.ClientToken)
			t.Log(testLogVaultSecret(t, secret))

			// token sanity check
			t2, err := secret.TokenID()
			require.NoError(err)
			assert.NotEmpty(t2)
			require.Equal(token, t2)
			require.Equal(t2, secret.Auth.ClientToken)

			if tt.tokenChkFn != nil {
				tt.tokenChkFn(t, secret)
			}

			tokenLookup := v.LookupToken(t, token)
			t.Log(testLogVaultSecret(t, tokenLookup))

			if tt.lookupChkFn != nil {
				tt.lookupChkFn(t, tokenLookup)
			}
		})
	}
}

func TestNewVaultServer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("TestNoTLS", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		v := NewTestVaultServer(t, WithTestVaultTLS(TestNoTLS))
		require.NotNil(v)

		assert.NotEmpty(v.RootToken)
		assert.NotEmpty(v.Addr)

		conf := &clientConfig{
			Addr:  v.Addr,
			Token: TokenSecret(v.RootToken),
		}

		client, err := newClient(ctx, conf)
		require.NoError(err)
		require.NotNil(client)
		require.NoError(client.ping(ctx))
	})
	t.Run("TestServerTLS", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		v := NewTestVaultServer(t, WithTestVaultTLS(TestServerTLS))
		require.NotNil(v)

		assert.NotEmpty(v.RootToken)
		assert.NotEmpty(v.Addr)
		assert.NotEmpty(v.CaCert)

		conf := &clientConfig{
			Addr:   v.Addr,
			Token:  TokenSecret(v.RootToken),
			CaCert: v.CaCert,
		}

		client, err := newClient(ctx, conf)
		require.NoError(err)
		require.NotNil(client)
		require.NoError(client.ping(ctx))
	})
	t.Run("TestServerTLS-InsecureSkipVerify", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		v := NewTestVaultServer(t, WithTestVaultTLS(TestServerTLS), WithServerCertHostNames([]string{"kaz"}))
		require.NotNil(v)

		assert.NotEmpty(v.RootToken)
		assert.NotEmpty(v.Addr)
		assert.NotEmpty(v.CaCert)

		conf := &clientConfig{
			Addr:   v.Addr,
			Token:  TokenSecret(v.RootToken),
			CaCert: v.CaCert,
		}

		client, err := newClient(ctx, conf)
		require.NoError(err)
		require.NotNil(client)
		require.Error(client.ping(ctx))

		conf.TlsSkipVerify = true
		client, err = newClient(ctx, conf)
		require.NoError(err)
		require.NotNil(client)
		require.NoError(client.ping(ctx))
	})
	t.Run("TestServerTLS-TlsServerName", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		v := NewTestVaultServer(t, WithTestVaultTLS(TestServerTLS), WithServerCertHostNames([]string{"kaz"}))
		require.NotNil(v)

		assert.NotEmpty(v.RootToken)
		assert.NotEmpty(v.Addr)
		assert.NotEmpty(v.CaCert)

		conf := &clientConfig{
			Addr:   v.Addr,
			Token:  TokenSecret(v.RootToken),
			CaCert: v.CaCert,
		}

		client, err := newClient(ctx, conf)
		require.NoError(err)
		require.NotNil(client)
		require.Error(client.ping(ctx))

		conf.TlsServerName = "kaz"
		client, err = newClient(ctx, conf)
		require.NoError(err)
		require.NotNil(client)
		require.NoError(client.ping(ctx))
	})
	t.Run("TestClientTLS", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		v := NewTestVaultServer(t, WithTestVaultTLS(TestClientTLS))
		require.NotNil(v)

		assert.NotEmpty(v.RootToken)
		assert.NotEmpty(v.Addr)
		assert.NotEmpty(v.CaCert)
		assert.NotEmpty(v.ClientCert)
		assert.NotEmpty(v.ClientKey)

		conf := &clientConfig{
			Addr:       v.Addr,
			Token:      TokenSecret(v.RootToken),
			CaCert:     v.CaCert,
			ClientCert: v.ClientCert,
			ClientKey:  v.ClientKey,
		}

		client, err := newClient(ctx, conf)
		require.NoError(err)
		require.NotNil(client)
		require.NoError(client.ping(ctx))
	})
	t.Run("TestClientTLS-with-client-key", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(err)

		v := NewTestVaultServer(t, WithTestVaultTLS(TestClientTLS), WithClientKey(key))
		require.NotNil(v)

		assert.NotEmpty(v.RootToken)
		assert.NotEmpty(v.Addr)
		assert.NotEmpty(v.CaCert)
		assert.NotEmpty(v.ClientCert)
		assert.NotEmpty(v.ClientKey)

		k, err := x509.MarshalECPrivateKey(key)
		require.NoError(err)
		assert.Equal(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: k}), v.ClientKey)

		conf := &clientConfig{
			Addr:          v.Addr,
			Token:         TokenSecret(v.RootToken),
			CaCert:        v.CaCert,
			TlsServerName: v.TlsServerName,
			TlsSkipVerify: v.TlsSkipVerify,
			ClientCert:    v.ClientCert,
			ClientKey:     v.ClientKey,
		}

		client, err := newClient(ctx, conf)
		require.NoError(err)
		require.NotNil(client)
		require.NoError(client.ping(ctx))
	})
}

func TestTestVaultServer_MountPKI(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		v := NewTestVaultServer(t, WithTestVaultTLS(TestNoTLS))
		require.NotNil(v)

		vc := v.client(t).cl
		mounts, err := vc.Sys().ListMounts()
		assert.NoError(err)
		require.NotEmpty(mounts)
		beforeCount := len(mounts)

		v.MountPKI(t)

		mounts, err = vc.Sys().ListMounts()
		assert.NoError(err)
		require.NotEmpty(mounts)
		afterCount := len(mounts)
		assert.Greater(afterCount, beforeCount)

		_, token := v.CreateToken(t, WithPolicies([]string{"default", "pki"}))
		vc.SetToken(token)

		certPath := path.Join("pki", "issue", "boundary")
		certOptions := map[string]any{
			"common_name": "boundary.com",
		}
		certSecret, err := vc.Logical().Write(certPath, certOptions)
		assert.NoError(err)
		require.NotEmpty(certSecret)
	})
	t.Run("with-mount-path", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		v := NewTestVaultServer(t, WithTestVaultTLS(TestServerTLS))
		require.NotNil(v)

		vc := v.client(t).cl
		mounts, err := vc.Sys().ListMounts()
		assert.NoError(err)
		require.NotEmpty(mounts)
		beforeCount := len(mounts)

		v.MountPKI(t, WithTestMountPath("gary"))

		mounts, err = vc.Sys().ListMounts()
		assert.NoError(err)
		require.NotEmpty(mounts)
		afterCount := len(mounts)
		assert.Greater(afterCount, beforeCount)

		_, token := v.CreateToken(t, WithPolicies([]string{"default", "pki"}))
		vc.SetToken(token)

		certPath := path.Join("gary", "issue", "boundary")
		certOptions := map[string]any{
			"common_name": "boundary.com",
		}
		certSecret, err := vc.Logical().Write(certPath, certOptions)
		assert.NoError(err)
		require.NotEmpty(certSecret)
	})
	t.Run("with-role-name", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		v := NewTestVaultServer(t, WithTestVaultTLS(TestClientTLS))
		require.NotNil(v)

		vc := v.client(t).cl
		mounts, err := vc.Sys().ListMounts()
		assert.NoError(err)
		require.NotEmpty(mounts)
		beforeCount := len(mounts)

		v.MountPKI(t, WithTestRoleName("gary"))

		mounts, err = vc.Sys().ListMounts()
		assert.NoError(err)
		require.NotEmpty(mounts)
		afterCount := len(mounts)
		assert.Greater(afterCount, beforeCount)

		_, token := v.CreateToken(t, WithPolicies([]string{"default", "pki"}))
		vc.SetToken(token)

		certPath := path.Join("pki", "issue", "gary")
		certOptions := map[string]any{
			"common_name": "boundary.com",
		}
		certSecret, err := vc.Logical().Write(certPath, certOptions)
		assert.NoError(err)
		require.NotEmpty(certSecret)
	})
}

func TestTestVaultServer_MountDatabase(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		v := NewTestVaultServer(t, WithDockerNetwork(true), WithTestVaultTLS(TestClientTLS))
		vc := v.client(t).cl

		mounts, err := vc.Sys().ListMounts()
		assert.NoError(err)
		require.NotEmpty(mounts)
		beforeCount := len(mounts)

		testDatabase := v.MountDatabase(t)

		mounts, err = vc.Sys().ListMounts()
		assert.NoError(err)
		require.NotEmpty(mounts)
		afterCount := len(mounts)

		assert.Greater(afterCount, beforeCount)

		_, token := v.CreateToken(t, WithPolicies([]string{"default", "boundary-controller", "database"}))
		vc.SetToken(token)

		dbSecret, err := vc.Logical().Read(path.Join("database", "creds", "opened"))
		assert.NoError(err)
		require.NotEmpty(dbSecret)

		// verify the database credentials work
		assert.NoError(testDatabase.ValidateCredential(t, dbSecret))

		// revoke the database credentials
		assert.NoError(vc.Sys().Revoke(dbSecret.LeaseID))

		// verify the database credentials no longer work
		assert.Error(testDatabase.ValidateCredential(t, dbSecret))
	})
}

func TestTestVaultServer_LookupLease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)

	conf := &clientConfig{
		Addr:       v.Addr,
		CaCert:     v.CaCert,
		ClientCert: v.ClientCert,
		ClientKey:  v.ClientKey,
		Token:      TokenSecret(v.RootToken),
	}

	client, err := newClient(ctx, conf)
	require.NoError(err)
	require.NotNil(client)
	assert.NoError(client.ping(ctx))

	// Create secret
	credPath := path.Join("database", "creds", "opened")
	cred, err := client.get(ctx, credPath)
	require.NoError(err)

	// Sleep to move ttl
	time.Sleep(time.Second)

	leaseLookup := v.LookupLease(t, cred.LeaseID)
	require.NotNil(leaseLookup.Data)

	id := leaseLookup.Data["id"]
	require.NotEmpty(id)
	assert.Equal(cred.LeaseID, id.(string))

	ttl := leaseLookup.Data["ttl"]
	require.NotEmpty(ttl)
	newTtl, err := ttl.(json.Number).Int64()
	require.NoError(err)
	// New ttl should have moved and be lower than original lease duration
	assert.True(cred.LeaseDuration > int(newTtl))
}

func TestTestVaultServer_VerifyTokenInvalid(t *testing.T) {
	t.Parallel()
	v := NewTestVaultServer(t, WithDockerNetwork(true))

	_, token := v.CreateToken(t)
	v.RevokeToken(t, token)
	v.VerifyTokenInvalid(t, token)

	// Verify fake token is not valid
	v.VerifyTokenInvalid(t, "fake-token")
}

func TestTestVaultServer_RevokeToken(t *testing.T) {
	t.Parallel()
	v := NewTestVaultServer(t, WithDockerNetwork(true))

	_, token := v.CreateToken(t)

	// Validate we can lookup the token
	v.LookupToken(t, token)

	v.RevokeToken(t, token)
	v.VerifyTokenInvalid(t, token)
}

func Test_testClientCert(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	cert := testClientCert(t, testCaCert(t))
	require.NotNil(cert)
	assert.NotEmpty(cert.Cert.Cert)
	assert.NotEmpty(cert.Cert.Key)

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(err)

	cert1 := testClientCert(t, testCaCert(t), WithClientKey(key))
	require.NotNil(cert1)
	assert.NotEmpty(cert1.Cert.Cert)
	assert.NotEmpty(cert1.Cert.Key)

	// cert and cert1 should have different certs and keys
	assert.NotEqual(cert1.Cert.Cert, cert.Cert.Cert)
	assert.NotEqual(cert1.Cert.Key, cert.Cert.Key)

	// Generate new cert with same key as cert1
	cert2 := testClientCert(t, testCaCert(t), WithClientKey(key))
	require.NotNil(cert2)
	assert.NotEmpty(cert2.Cert.Cert)
	assert.NotEmpty(cert2.Cert.Key)

	// cert1 and cert2 should have different certs but the same key
	assert.NotEqual(cert1.Cert.Cert, cert2.Cert.Cert)
	assert.Equal(cert1.Cert.Key, cert2.Cert.Key)
}

func TestTestVaultServer_AddKVPolicy(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		assert, require := assert.New(t), require.New(t)
		v := NewTestVaultServer(t)

		sec := v.CreateKVSecret(t, "my-secret", []byte(`{"data" : {"foo":"bar"}}`))
		require.NotNil(sec)

		_, token := v.CreateToken(t, WithPolicies([]string{"default", "secret"}))
		require.NotNil(token)
		client := v.ClientUsingToken(t, token)

		_, err := client.get(ctx, "/secret/data/my-secret")
		assert.Error(err)

		// An attempt to get my-secret should now fail with a 403
		var respErr *vault.ResponseError
		ok := errors.As(err, &respErr)
		require.True(ok)
		assert.Equal(http.StatusForbidden, respErr.StatusCode)

		// Add KV policy and get should work
		v.AddKVPolicy(t)
		_, token = v.CreateToken(t, WithPolicies([]string{"default", "secret"}))
		require.NotNil(token)
		client = v.ClientUsingToken(t, token)

		_, err = client.get(ctx, "/secret/data/my-secret")
		assert.NoError(err)
	})
}

func TestTestVaultServer_CreateKVSecret(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		v := NewTestVaultServer(t)
		vc := v.client(t)

		// Attempt to read my-secret should return a nil secret
		got, err := vc.cl.Logical().Read("/secret/data/my-secret")
		require.NoError(err)
		require.Nil(got)

		secret := v.CreateKVSecret(t, "my-secret", []byte(`{"data" : {"foo":"bar"}}`))
		require.NotNil(secret)

		// Now that secret exists try read again
		got, err = vc.cl.Logical().Read("/secret/data/my-secret")
		require.NoError(err)
		require.NotNil(got)
		require.NotNil(got.Data)
		require.NotNil(got.Data["data"])

		gotData, ok := got.Data["data"].(map[string]any)
		require.True(ok)
		require.NotNil(gotData["foo"])

		gotFoo, ok := gotData["foo"].(string)
		require.True(ok)
		assert.Equal("bar", gotFoo)
	})
}
