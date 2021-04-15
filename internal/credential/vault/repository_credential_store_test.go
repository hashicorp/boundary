package vault

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateCredentialStoreResource(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

		v, cleanup := NewTestVaultServer(t, TestNoTLS)
		defer cleanup()
		secret := v.CreateToken(t)
		token := secret.Auth.ClientToken

		in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token), WithName("gary"), WithDescription("46"))
		assert.NoError(err)
		require.NotNil(in)
		assert.NotEmpty(in.Name)
		got, err := repo.CreateCredentialStore(ctx, in)

		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, CredentialStorePrefix, got.PublicId)

		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateCredentialStore(ctx, in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-scopes", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

		v, cleanup := NewTestVaultServer(t, TestNoTLS)
		defer cleanup()

		secret1 := v.CreateToken(t)
		token1 := secret1.Auth.ClientToken
		in1, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token1), WithName("gary"), WithDescription("46"))
		assert.NoError(err)
		require.NotNil(in1)
		assert.NotEmpty(in1.Name)
		got1, err := repo.CreateCredentialStore(ctx, in1)
		require.NoError(err)
		require.NotNil(got1)
		assertPublicId(t, CredentialStorePrefix, got1.PublicId)
		assert.NotSame(in1, got1)
		assert.Equal(in1.Name, got1.Name)
		assert.Equal(in1.Description, got1.Description)
		assert.Equal(got1.CreateTime, got1.UpdateTime)

		secret2 := v.CreateToken(t)
		token2 := secret2.Auth.ClientToken
		in2, err := NewCredentialStore(org.GetPublicId(), v.Addr, []byte(token2), WithName("gary"), WithDescription("46"))
		assert.NoError(err)
		require.NotNil(in2)
		assert.NotEmpty(in2.Name)
		in2.ScopeId = org.GetPublicId()
		got2, err := repo.CreateCredentialStore(ctx, in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, CredentialStorePrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)

		assert.Equal(in1.Name, in2.Name)
		assert.Equal(got1.Name, got2.Name)
	})
}

func assertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}

func TestRepository_CreateCredentialStoreNonResource(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	tests := []struct {
		name      string
		tls       TestVaultTLS
		tokenOpts []TestOption
		wantIsErr errors.Code
	}{
		{
			name: "no-tls-valid-token",
		},
		{
			name: "server-tls-valid-token",
			tls:  TestServerTLS,
		},
		{
			name: "client-tls-valid-token",
			tls:  TestClientTLS,
		},
		{
			name:      "no-tls-token-not-renewable",
			tokenOpts: []TestOption{TestRenewableToken(t, false)},
			wantIsErr: errors.VaultTokenNotRenewable,
		},
		{
			name:      "no-tls-token-not-orphaned",
			tokenOpts: []TestOption{TestOrphanToken(t, false)},
			wantIsErr: errors.VaultTokenNotOrphaned,
		},
		{
			name:      "no-tls-token-not-periodic",
			tokenOpts: []TestOption{TestPeriodicToken(t, false)},
			wantIsErr: errors.VaultTokenNotPeriodic,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

			v, cleanup := NewTestVaultServer(t, tt.tls)
			defer cleanup()
			secret := v.CreateToken(t, tt.tokenOpts...)
			token := secret.Auth.ClientToken

			var opts []Option
			if tt.tls == TestServerTLS {
				opts = append(opts, WithCACert(v.CaCert))
			}
			if tt.tls == TestClientTLS {
				opts = append(opts, WithCACert(v.CaCert))
				clientCert, err := NewClientCertificate(v.ClientCert, v.ClientKey)
				require.NoError(err)
				opts = append(opts, WithClientCert(clientCert))
			}

			credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token), opts...)
			assert.NoError(err)
			require.NotNil(credStoreIn)
			got, err := repo.CreateCredentialStore(ctx, credStoreIn)

			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				if got != nil {
					err := db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
					require.Errorf(err, "should not have found oplog entry for %s", got.PublicId)
				}
				return
			}
			require.NoError(err)
			assert.Empty(credStoreIn.PublicId)
			require.NotNil(got)
			assertPublicId(t, CredentialStorePrefix, got.PublicId)
			assert.NotSame(credStoreIn, got)
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

			outToken := allocToken()
			assert.NoError(rw.LookupWhere(ctx, &outToken, "store_id = ?", got.PublicId))

			if tt.tls == TestClientTLS {
				outClientCert := allocClientCertificate()
				assert.NoError(rw.LookupWhere(ctx, &outClientCert, "store_id = ?", got.PublicId))
			}
		})
	}
}

func TestRepository_LookupCredentialStore(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	stores := TestCredentialStores(t, conn, wrapper, prj.PublicId, 2)
	csWithClientCert := stores[0]
	csWithoutClientCert := stores[1]

	ccert := allocClientCertificate()
	rows, err := rw.Delete(context.Background(), ccert, db.WithWhere("store_id = ?", csWithoutClientCert.GetPublicId()))
	require.NoError(t, err)
	require.Equal(t, 1, rows)

	badId, err := newCredentialStoreId()
	assert.NoError(t, err)
	require.NotNil(t, badId)

	// TODO(mgaffney) 04/2021: Add test for credential stores with no
	// 'current' token
	tests := []struct {
		name           string
		id             string
		want           *CredentialStore
		wantClientCert bool
		wantErr        errors.Code
	}{
		{
			name:           "valid-with-client-cert",
			id:             csWithClientCert.GetPublicId(),
			want:           csWithClientCert,
			wantClientCert: true,
		},
		{
			name:           "valid-without-client-cert",
			id:             csWithoutClientCert.GetPublicId(),
			want:           csWithoutClientCert,
			wantClientCert: false,
		},
		{
			name:    "empty-public-id",
			id:      "",
			wantErr: errors.InvalidParameter,
		},
		{
			name: "not-found",
			id:   badId,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			got, err := repo.LookupCredentialStore(ctx, tt.id)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)

			if tt.want == nil {
				assert.Nil(got)
				return
			}

			assert.NotNil(got)
			assert.NotSame(got, tt.want)
			assert.NotNil(got.Token(), "token")

			if tt.wantClientCert {
				assert.NotNil(got.ClientCertificate(), "client certificate")
			} else {
				assert.Nil(got.ClientCertificate(), "client certificate")
			}
		})
	}
}
