package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_IssueCredentials(t *testing.T) {
	t.Skip("not implemented")
}

func TestRepository_getPrivateLibraries(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	tests := []struct {
		name string
		tls  TestVaultTLS
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

			v := NewTestVaultServer(t, WithTestVaultTLS(tt.tls))

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

			secret := v.CreateToken(t)
			token := secret.Auth.ClientToken

			credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token), opts...)
			assert.NoError(err)
			require.NotNil(credStoreIn)
			origStore, err := repo.CreateCredentialStore(ctx, credStoreIn)
			assert.NoError(err)
			require.NotNil(origStore)

			origLookup, err := repo.LookupCredentialStore(ctx, origStore.GetPublicId())
			assert.NoError(err)
			require.NotNil(origLookup)
			assert.NotNil(origLookup.Token())
			assert.Equal(origStore.GetPublicId(), origLookup.GetPublicId())

			libs := make(map[string]*CredentialLibrary, 3)
			var libIds []string
			{
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path")
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				libIds = append(libIds, lib.GetPublicId())
			}
			{
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", WithMethod(MethodPost))
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				libIds = append(libIds, lib.GetPublicId())
			}
			{
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", WithMethod(MethodPost), WithRequestBody([]byte(`{"common_name":"boundary.com"}`)))
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				libIds = append(libIds, lib.GetPublicId())
			}

			gotLibs, err := repo.getPrivateLibraries(ctx, libIds)
			assert.NoError(err)
			require.NotNil(gotLibs)
			assert.Len(gotLibs, len(libs))

			for _, got := range gotLibs {
				assert.Equal([]byte(token), got.Token)
				if tt.tls == TestClientTLS {
					require.NotNil(got.ClientKey)
					assert.Equal(v.ClientKey, got.ClientKey)
				}
				want, ok := libs[got.PublicId]
				require.True(ok)
				assert.Equal(prj.GetPublicId(), got.ScopeId)
				assert.Equal(want.StoreId, got.StoreId)
				assert.Equal(want.VaultPath, got.VaultPath)
				assert.Equal(want.HttpMethod, got.HttpMethod)
				assert.Equal(want.HttpRequestBody, got.HttpRequestBody)
			}
		})
	}
}
