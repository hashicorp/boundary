package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_getPrivateLibraries(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	sche := scheduler.TestScheduler(t, conn, wrapper)

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

			repo, err := NewRepository(rw, rw, kms, sche)
			require.NoError(err)
			require.NotNil(repo)
			err = RegisterJobs(ctx, sche, rw, rw, kms)
			require.NoError(err)

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

			_, token := v.CreateToken(t)

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
			var requests []credential.Request
			{
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path")
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.ApplicationPurpose}
				requests = append(requests, req)
			}
			{
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", WithMethod(MethodPost))
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.ApplicationPurpose}
				requests = append(requests, req)
			}
			{
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", WithMethod(MethodPost), WithRequestBody([]byte(`{"common_name":"boundary.com"}`)))
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.ApplicationPurpose}
				requests = append(requests, req)
			}

			gotLibs, err := repo.getPrivateLibraries(ctx, requests)
			assert.NoError(err)
			require.NotNil(gotLibs)
			assert.Len(gotLibs, len(libs))

			for _, got := range gotLibs {
				assert.Equal(TokenSecret(token), got.Token)
				if tt.tls == TestClientTLS {
					require.NotNil(got.ClientKey)
					assert.Equal(v.ClientKey, []byte(got.ClientKey))
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

func TestRequestMap(t *testing.T) {
	type args struct {
		requests []credential.Request
	}

	tests := []struct {
		name       string
		args       args
		wantLibIds []string
		wantErr    bool
	}{
		{
			name: "empty",
		},
		{
			name: "one",
			args: args{
				requests: []credential.Request{
					{
						SourceId: "kaz",
						Purpose:  credential.ApplicationPurpose,
					},
				},
			},
			wantLibIds: []string{"kaz"},
		},
		{
			name: "two-libs",
			args: args{
				requests: []credential.Request{
					{
						SourceId: "kaz",
						Purpose:  credential.ApplicationPurpose,
					},
					{
						SourceId: "gary",
						Purpose:  credential.EgressPurpose,
					},
				},
			},
			wantLibIds: []string{"kaz", "gary"},
		},
		{
			name: "one-lib-two-purps",
			args: args{
				requests: []credential.Request{
					{
						SourceId: "kaz",
						Purpose:  credential.ApplicationPurpose,
					},
					{
						SourceId: "kaz",
						Purpose:  credential.EgressPurpose,
					},
				},
			},
			wantLibIds: []string{"kaz"},
		},
		{
			name: "one-lib-dup-purps-error",
			args: args{
				requests: []credential.Request{
					{
						SourceId: "kaz",
						Purpose:  credential.ApplicationPurpose,
					},
					{
						SourceId: "kaz",
						Purpose:  credential.ApplicationPurpose,
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			mapper, err := newMapper(tt.args.requests)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(mapper)
				return
			}
			assert.NoError(err)
			require.NotNil(mapper)
			assert.ElementsMatch(tt.wantLibIds, mapper.libIds())
		})
	}
}
