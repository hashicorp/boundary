package vault

import (
	"encoding/json"
	"path"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
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
	libs := TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), count)
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
			lookupChkFn: assertIsPeriodic(),
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
			lookupChkFn: assertIsPeriodic(),
		},
		{
			name:        "NotRenewable",
			opts:        []TestOption{TestRenewableToken(false)},
			tokenChkFn:  combine(assertIsNotRenewable(), assertIsOrphan()),
			lookupChkFn: assertIsPeriodic(),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			v := NewTestVaultServer(t)
			require.NotNil(v)
			secret := v.CreateToken(t, tt.opts...)
			require.NotNil(secret)
			t.Log(testLogVaultSecret(t, secret))

			// token sanity check
			token, err := secret.TokenID()
			require.NoError(err)
			assert.NotEmpty(token)
			require.Equal(token, secret.Auth.ClientToken)

			if tt.tokenChkFn != nil {
				tt.tokenChkFn(t, secret)
			}

			tokenLookup := v.LookupToken(t, token)
			require.NotNil(tokenLookup)
			t.Log(testLogVaultSecret(t, tokenLookup))

			if tt.lookupChkFn != nil {
				tt.lookupChkFn(t, tokenLookup)
			}
		})
	}
}

func TestNewVaultServer(t *testing.T) {
	t.Parallel()
	t.Run("TestNoTLS", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		v := NewTestVaultServer(t, WithTestVaultTLS(TestNoTLS))
		require.NotNil(v)

		assert.NotEmpty(v.RootToken)
		assert.NotEmpty(v.Addr)

		conf := &clientConfig{
			Addr:  v.Addr,
			Token: v.RootToken,
		}

		client, err := newClient(conf)
		require.NoError(err)
		require.NotNil(client)
		require.NoError(client.ping())
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
			Token:  v.RootToken,
			CaCert: v.CaCert,
		}

		client, err := newClient(conf)
		require.NoError(err)
		require.NotNil(client)
		require.NoError(client.ping())
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
			Token:      v.RootToken,
			CaCert:     v.CaCert,
			ClientCert: v.ClientCert,
			ClientKey:  v.ClientKey,
		}

		client, err := newClient(conf)
		require.NoError(err)
		require.NotNil(client)
		require.NoError(client.ping())
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

		token := v.CreateToken(t, WithPolicies([]string{"default", "pki"}))
		vc.SetToken(token.Auth.ClientToken)

		certPath := path.Join("pki", "issue", "boundary")
		certOptions := map[string]interface{}{
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

		token := v.CreateToken(t, WithPolicies([]string{"default", "pki"}))
		vc.SetToken(token.Auth.ClientToken)

		certPath := path.Join("gary", "issue", "boundary")
		certOptions := map[string]interface{}{
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

		token := v.CreateToken(t, WithPolicies([]string{"default", "pki"}))
		vc.SetToken(token.Auth.ClientToken)

		certPath := path.Join("pki", "issue", "gary")
		certOptions := map[string]interface{}{
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
		require.NotNil(v)

		vc := v.client(t).cl
		mounts, err := vc.Sys().ListMounts()
		assert.NoError(err)
		require.NotEmpty(mounts)
		beforeCount := len(mounts)

		v.MountDatabase(t)

		mounts, err = vc.Sys().ListMounts()
		assert.NoError(err)
		require.NotEmpty(mounts)
		afterCount := len(mounts)
		assert.Greater(afterCount, beforeCount)

		token := v.CreateToken(t, WithPolicies([]string{"default", "database"}))
		vc.SetToken(token.Auth.ClientToken)

		dbCredPath := path.Join("database", "creds", "opened")
		dbSecret, err := vc.Logical().Read(dbCredPath)
		assert.NoError(err)
		require.NotEmpty(dbSecret)
	})
}
