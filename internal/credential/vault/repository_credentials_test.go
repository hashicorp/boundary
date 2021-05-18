package vault

import (
	"context"
	"path"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_IssueCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)
	v.MountPKI(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kms := kms.TestKms(t, conn, wrapper)

	assert, require := assert.New(t), require.New(t)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	secret := v.CreateToken(t, WithPolicies([]string{"default", "database", "pki"}))
	token := secret.Auth.ClientToken

	credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token))
	assert.NoError(err)
	require.NotNil(credStoreIn)
	origStore, err := repo.CreateCredentialStore(ctx, credStoreIn)
	assert.NoError(err)
	require.NotNil(origStore)

	type libT int
	const (
		libDB libT = iota
		libPKI
		libErrPKI
	)

	libs := make(map[libT]string)
	{
		libPath := path.Join("database", "creds", "opened")
		libIn, err := NewCredentialLibrary(origStore.GetPublicId(), libPath)
		assert.NoError(err)
		require.NotNil(libIn)
		lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
		assert.NoError(err)
		require.NotNil(lib)
		libs[libDB] = lib.GetPublicId()
	}
	{
		libPath := path.Join("pki", "issue", "boundary")
		libIn, err := NewCredentialLibrary(origStore.GetPublicId(), libPath, WithMethod(MethodPost), WithRequestBody([]byte(`{"common_name":"boundary.com"}`)))
		assert.NoError(err)
		require.NotNil(libIn)
		lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
		assert.NoError(err)
		require.NotNil(lib)
		libs[libPKI] = lib.GetPublicId()
	}
	{

		libPath := path.Join("pki", "issue", "boundary")
		libIn, err := NewCredentialLibrary(origStore.GetPublicId(), libPath, WithMethod(MethodPost))
		assert.NoError(err)
		require.NotNil(libIn)
		lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
		assert.NoError(err)
		require.NotNil(lib)
		libs[libErrPKI] = lib.GetPublicId()
	}

	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})

	tar := target.TestTcpTarget(t, conn, prj.GetPublicId(), "test", target.WithHostSets([]string{hs.GetPublicId()}))

	tests := []struct {
		name       string
		libraryIds []string
		wantErr    errors.Code
	}{
		{
			name:       "one-library-valid",
			libraryIds: []string{libs[libDB]},
		},
		{
			name:       "multiple-valid-libraries",
			libraryIds: []string{libs[libDB], libs[libPKI]},
		},
		{
			name:       "one-library-that-errors",
			libraryIds: []string{libs[libErrPKI]},
			wantErr:    errors.VaultCredentialRequest,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
				UserId:      uId,
				HostId:      h.GetPublicId(),
				TargetId:    tar.GetPublicId(),
				HostSetId:   hs.GetPublicId(),
				AuthTokenId: at.GetPublicId(),
				ScopeId:     prj.GetPublicId(),
				Endpoint:    "tcp://127.0.0.1:22",
			})
			got, err := repo.IssueCredentials(ctx, sess.GetPublicId(), tt.libraryIds)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			assert.Len(got, len(tt.libraryIds))
		})
	}
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
			v := NewTestVaultServer(t, WithTestVaultTLS(tt.tls))
			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			kms := kms.TestKms(t, conn, wrapper)

			repo, err := NewRepository(rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)

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
