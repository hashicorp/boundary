package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
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

			libs := make(map[string]*CredentialLibrary)
			var requests []credential.Request
			{
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path")
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.BrokeredPurpose}
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
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.BrokeredPurpose}
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
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.BrokeredPurpose}
				requests = append(requests, req)
			}
			{
				opts := []Option{
					WithCredentialType(credential.UsernamePasswordType),
				}
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", opts...)
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.BrokeredPurpose}
				requests = append(requests, req)
			}
			{
				opts := []Option{
					WithCredentialType(credential.UsernamePasswordType),
					WithMappingOverride(NewUsernamePasswordOverride(
						WithOverrideUsernameAttribute("test-username"),
					)),
				}
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", opts...)
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.BrokeredPurpose}
				requests = append(requests, req)
			}
			{
				opts := []Option{
					WithCredentialType(credential.UsernamePasswordType),
					WithMappingOverride(NewUsernamePasswordOverride(
						WithOverridePasswordAttribute("test-password"),
					)),
				}
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", opts...)
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.BrokeredPurpose}
				requests = append(requests, req)
			}
			{
				opts := []Option{
					WithCredentialType(credential.UsernamePasswordType),
					WithMappingOverride(NewUsernamePasswordOverride(
						WithOverrideUsernameAttribute("test-username"),
						WithOverridePasswordAttribute("test-password"),
					)),
				}
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", opts...)
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.BrokeredPurpose}
				requests = append(requests, req)
			}
			{
				opts := []Option{
					WithCredentialType(credential.SshPrivateKeyType),
				}
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", opts...)
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.BrokeredPurpose}
				requests = append(requests, req)
			}
			{
				opts := []Option{
					WithCredentialType(credential.SshPrivateKeyType),
					WithMappingOverride(NewSshPrivateKeyOverride(
						WithOverrideUsernameAttribute("test-username"),
					)),
				}
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", opts...)
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.BrokeredPurpose}
				requests = append(requests, req)
			}
			{
				opts := []Option{
					WithCredentialType(credential.SshPrivateKeyType),
					WithMappingOverride(NewSshPrivateKeyOverride(
						WithOverridePrivateKeyAttribute("test-private-key"),
					)),
				}
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", opts...)
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.BrokeredPurpose}
				requests = append(requests, req)
			}
			{
				opts := []Option{
					WithCredentialType(credential.SshPrivateKeyType),
					WithMappingOverride(NewSshPrivateKeyOverride(
						WithOverridePrivateKeyPassphraseAttribute("test-passphrase"),
					)),
				}
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", opts...)
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.BrokeredPurpose}
				requests = append(requests, req)
			}
			{
				opts := []Option{
					WithCredentialType(credential.SshPrivateKeyType),
					WithMappingOverride(NewSshPrivateKeyOverride(
						WithOverrideUsernameAttribute("test-username"),
						WithOverridePrivateKeyAttribute("test-private-key"),
						WithOverridePrivateKeyPassphraseAttribute("test-passphrase"),
					)),
				}
				libIn, err := NewCredentialLibrary(origStore.GetPublicId(), "/vault/path", opts...)
				assert.NoError(err)
				require.NotNil(libIn)
				lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
				assert.NoError(err)
				require.NotNil(lib)
				libs[lib.GetPublicId()] = lib
				req := credential.Request{SourceId: lib.GetPublicId(), Purpose: credential.BrokeredPurpose}
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
				assert.Equal(prj.GetPublicId(), got.ProjectId)
				assert.Equal(want.StoreId, got.StoreId)
				assert.Equal(want.VaultPath, got.VaultPath)
				assert.Equal(want.HttpMethod, got.HttpMethod)
				assert.Equal(want.HttpRequestBody, got.HttpRequestBody)
				assert.Equal(want.CredentialType(), got.CredentialType())
				if mo := want.MappingOverride; mo != nil {
					switch w := mo.(type) {
					case *UsernamePasswordOverride:
						assert.Equal(w.UsernameAttribute, got.UsernameAttribute)
						assert.Equal(w.PasswordAttribute, got.PasswordAttribute)
					case *SshPrivateKeyOverride:
						assert.Equal(w.UsernameAttribute, got.UsernameAttribute)
						assert.Equal(w.PrivateKeyAttribute, got.PrivateKeyAttribute)
						assert.Equal(w.PrivateKeyPassphraseAttribute, got.PrivateKeyPassphraseAttribute)
					default:
						assert.Fail("unknown mapping override type")
					}
				}
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
						Purpose:  credential.BrokeredPurpose,
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
						Purpose:  credential.BrokeredPurpose,
					},
					{
						SourceId: "gary",
						Purpose:  credential.InjectedApplicationPurpose,
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
						Purpose:  credential.BrokeredPurpose,
					},
					{
						SourceId: "kaz",
						Purpose:  credential.InjectedApplicationPurpose,
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
						Purpose:  credential.BrokeredPurpose,
					},
					{
						SourceId: "kaz",
						Purpose:  credential.BrokeredPurpose,
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

func TestBaseToUsrPass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		given   *baseCred
		want    *usrPassCred
		wantErr errors.Code
	}{
		{
			name:    "nil-input",
			wantErr: errors.InvalidParameter,
		},
		{
			name:    "nil-library",
			given:   &baseCred{},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "library-not-username-password-type",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UnspecifiedType),
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-username-default-password-attribute",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]interface{}{
					"password": "my-password",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-no-password-default-username-attribute",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]interface{}{
					"username": "my-username",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "valid-default-attributes",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]interface{}{
					"username": "my-username",
					"password": "my-password",
				},
			},
			want: &usrPassCred{
				username: "my-username",
				password: credential.Password("my-password"),
			},
		},
		{
			name: "valid-override-attributes",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:          string(credential.UsernamePasswordType),
					UsernameAttribute: "test-username",
					PasswordAttribute: "test-password",
				},
				secretData: map[string]interface{}{
					"username":      "default-username",
					"password":      "default-password",
					"test-username": "override-username",
					"test-password": "override-password",
				},
			},
			want: &usrPassCred{
				username: "override-username",
				password: credential.Password("override-password"),
			},
		},
		{
			name: "valid-default-username-override-password",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:          string(credential.UsernamePasswordType),
					PasswordAttribute: "test-password",
				},
				secretData: map[string]interface{}{
					"username":      "default-username",
					"password":      "default-password",
					"test-username": "override-username",
					"test-password": "override-password",
				},
			},
			want: &usrPassCred{
				username: "default-username",
				password: credential.Password("override-password"),
			},
		},
		{
			name: "valid-override-username-default-password",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:          string(credential.UsernamePasswordType),
					UsernameAttribute: "test-username",
				},
				secretData: map[string]interface{}{
					"username":      "default-username",
					"password":      "default-password",
					"test-username": "override-username",
					"test-password": "override-password",
				},
			},
			want: &usrPassCred{
				username: "override-username",
				password: credential.Password("default-password"),
			},
		},
		{
			name: "invalid-username-override",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:          string(credential.UsernamePasswordType),
					UsernameAttribute: "missing-username",
				},
				secretData: map[string]interface{}{
					"username":      "default-username",
					"password":      "default-password",
					"test-username": "override-username",
					"test-password": "override-password",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-password-override",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:          string(credential.UsernamePasswordType),
					UsernameAttribute: "missing-password",
				},
				secretData: map[string]interface{}{
					"username":      "default-username",
					"password":      "default-password",
					"test-username": "override-username",
					"test-password": "override-password",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-metadata-field",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]interface{}{
					"data": map[string]interface{}{
						"username": "my-username",
						"password": "my-password",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-data-field",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-username-default-password-attribute",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"password": "my-password",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-passsword-default-username-attribute",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username": "my-username",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-invalid-metadata-type",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]interface{}{
					"metadata": "hello",
					"data": map[string]interface{}{
						"username": "my-username",
						"password": "my-password",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-invalid-metadata-type",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data":     "hello",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-additional-field",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]interface{}{
					"bad-field": "hello",
					"metadata":  map[string]interface{}{},
					"data": map[string]interface{}{
						"username": "my-username",
						"password": "my-password",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "valid-kv2-default-attributes",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username": "my-username",
						"password": "my-password",
					},
				},
			},
			want: &usrPassCred{
				username: "my-username",
				password: credential.Password("my-password"),
			},
		},
		{
			name: "valid-kv2-override-attributes",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:          string(credential.UsernamePasswordType),
					UsernameAttribute: "test-username",
					PasswordAttribute: "test-password",
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":      "default-username",
						"password":      "default-password",
						"test-username": "override-username",
						"test-password": "override-password",
					},
				},
			},
			want: &usrPassCred{
				username: "override-username",
				password: credential.Password("override-password"),
			},
		},
		{
			name: "valid-kv2-default-username-override-password",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:          string(credential.UsernamePasswordType),
					PasswordAttribute: "test-password",
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":      "default-username",
						"password":      "default-password",
						"test-username": "override-username",
						"test-password": "override-password",
					},
				},
			},
			want: &usrPassCred{
				username: "default-username",
				password: credential.Password("override-password"),
			},
		},
		{
			name: "valid-kv2-override-username-default-password",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:          string(credential.UsernamePasswordType),
					UsernameAttribute: "test-username",
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":      "default-username",
						"password":      "default-password",
						"test-username": "override-username",
						"test-password": "override-password",
					},
				},
			},
			want: &usrPassCred{
				username: "override-username",
				password: credential.Password("default-password"),
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := baseToUsrPass(context.Background(), tt.given)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			want := tt.want
			want.baseCred = tt.given
			assert.Equal(want, got)
		})
	}
}

func TestBaseToSshPriKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		given   *baseCred
		want    *sshPrivateKeyCred
		wantErr errors.Code
	}{
		{
			name:    "nil-input",
			wantErr: errors.InvalidParameter,
		},
		{
			name:    "nil-library",
			given:   &baseCred{},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "library-not-ssh-private-key-type",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.UnspecifiedType),
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-username-default-pk-attribute",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"private_key": "my-pk",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-no-pk-default-username-attribute",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"username": "my-username",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "valid-default-attributes",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"username":    "my-username",
					"private_key": "my-pk",
				},
			},
			want: &sshPrivateKeyCred{
				username:   "my-username",
				privateKey: credential.PrivateKey("my-pk"),
			},
		},
		{
			name: "valid-default-attributes-with-passphrase",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"username":               "my-username",
					"private_key":            "my-pk",
					"private_key_passphrase": "my-pass",
				},
			},
			want: &sshPrivateKeyCred{
				username:   "my-username",
				privateKey: credential.PrivateKey("my-pk"),
				passphrase: []byte("my-pass"),
			},
		},
		{
			name: "valid-override-attributes",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:            string(credential.SshPrivateKeyType),
					UsernameAttribute:   "test-username",
					PrivateKeyAttribute: "test-pk",
				},
				secretData: map[string]interface{}{
					"username":      "default-username",
					"private_key":   "default-pk",
					"test-username": "override-username",
					"test-pk":       "override-pk",
				},
			},
			want: &sshPrivateKeyCred{
				username:   "override-username",
				privateKey: credential.PrivateKey("override-pk"),
			},
		},
		{
			name: "valid-override-attributes-with-passphrase",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:                      string(credential.SshPrivateKeyType),
					UsernameAttribute:             "test-username",
					PrivateKeyAttribute:           "test-pk",
					PrivateKeyPassphraseAttribute: "test-pass",
				},
				secretData: map[string]interface{}{
					"username":      "default-username",
					"private_key":   "default-pk",
					"passphrase":    "default-pass",
					"test-username": "override-username",
					"test-pk":       "override-pk",
					"test-pass":     "override-pass",
				},
			},
			want: &sshPrivateKeyCred{
				username:   "override-username",
				privateKey: credential.PrivateKey("override-pk"),
				passphrase: []byte("override-pass"),
			},
		},
		{
			name: "valid-default-username-override-pk",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:            string(credential.SshPrivateKeyType),
					PrivateKeyAttribute: "test-pk",
				},
				secretData: map[string]interface{}{
					"username":      "default-username",
					"private_key":   "default-pk",
					"test-username": "override-username",
					"test-pk":       "override-pk",
				},
			},
			want: &sshPrivateKeyCred{
				username:   "default-username",
				privateKey: credential.PrivateKey("override-pk"),
			},
		},
		{
			name: "valid-override-username-default-pk",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:          string(credential.SshPrivateKeyType),
					UsernameAttribute: "test-username",
				},
				secretData: map[string]interface{}{
					"username":      "default-username",
					"private_key":   "default-pk",
					"test-username": "override-username",
					"test-pk":       "override-pk",
				},
			},
			want: &sshPrivateKeyCred{
				username:   "override-username",
				privateKey: credential.PrivateKey("default-pk"),
			},
		},
		{
			name: "invalid-username-override",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:          string(credential.SshPrivateKeyType),
					UsernameAttribute: "missing-username",
				},
				secretData: map[string]interface{}{
					"username":      "default-username",
					"private_key":   "default-pk",
					"test-username": "override-username",
					"test-pk":       "override-pk",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-pk-override",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:          string(credential.SshPrivateKeyType),
					UsernameAttribute: "missing-pk",
				},
				secretData: map[string]interface{}{
					"username":      "default-username",
					"private_key":   "default-pk",
					"test-username": "override-username",
					"test-pk":       "override-pk",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-metadata-field",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"data": map[string]interface{}{
						"username":    "default-username",
						"private_key": "default-pk",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-data-field",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-username-default-pk-attribute",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"private_key": "default-pk",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-pk-default-username-attribute",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username": "default-username",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-invalid-metadata-type",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"metadata": "hello",
					"data": map[string]interface{}{
						"username":    "default-username",
						"private_key": "default-pk",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-invalid-data-type",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data":     "hello",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-additional-field",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"bad-field": "hello",
					"metadata":  map[string]interface{}{},
					"data": map[string]interface{}{
						"username":    "default-username",
						"private_key": "default-pk",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "valid-kv2-default-attributes",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":    "default-username",
						"private_key": "default-pk",
					},
				},
			},
			want: &sshPrivateKeyCred{
				username:   "default-username",
				privateKey: credential.PrivateKey("default-pk"),
			},
		},
		{
			name: "valid-kv2-default-attributes-with-passphrase",
			given: &baseCred{
				lib: &privateLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":               "default-username",
						"private_key":            "default-pk",
						"private_key_passphrase": "default-pass",
					},
				},
			},
			want: &sshPrivateKeyCred{
				username:   "default-username",
				privateKey: credential.PrivateKey("default-pk"),
				passphrase: []byte("default-pass"),
			},
		},
		{
			name: "valid-kv2-override-attributes",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:            string(credential.SshPrivateKeyType),
					UsernameAttribute:   "test-username",
					PrivateKeyAttribute: "test-pk",
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":      "default-username",
						"private_key":   "default-pk",
						"test-username": "override-username",
						"test-pk":       "override-pk",
					},
				},
			},
			want: &sshPrivateKeyCred{
				username:   "override-username",
				privateKey: credential.PrivateKey("override-pk"),
			},
		},
		{
			name: "valid-kv2-override-attributes-with-passphrase",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:                      string(credential.SshPrivateKeyType),
					UsernameAttribute:             "test-username",
					PrivateKeyAttribute:           "test-pk",
					PrivateKeyPassphraseAttribute: "test-pass",
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":      "default-username",
						"private_key":   "default-pk",
						"passphrase":    "default-pass",
						"test-username": "override-username",
						"test-pk":       "override-pk",
						"test-pass":     "override-pass",
					},
				},
			},
			want: &sshPrivateKeyCred{
				username:   "override-username",
				privateKey: credential.PrivateKey("override-pk"),
				passphrase: []byte("override-pass"),
			},
		},
		{
			name: "valid-kv2-default-username-override-pk",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:            string(credential.SshPrivateKeyType),
					PrivateKeyAttribute: "test-pk",
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":      "default-username",
						"private_key":   "default-pk",
						"test-username": "override-username",
						"test-pk":       "override-pk",
					},
				},
			},
			want: &sshPrivateKeyCred{
				username:   "default-username",
				privateKey: credential.PrivateKey("override-pk"),
			},
		},
		{
			name: "valid-kv2-override-username-default-pk",
			given: &baseCred{
				lib: &privateLibrary{
					CredType:          string(credential.SshPrivateKeyType),
					UsernameAttribute: "test-username",
				},
				secretData: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":      "default-username",
						"private_key":   "default-pk",
						"test-username": "override-username",
						"test-pk":       "override-pk",
					},
				},
			},
			want: &sshPrivateKeyCred{
				username:   "override-username",
				privateKey: credential.PrivateKey("default-pk"),
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := baseToSshPriKey(context.Background(), tt.given)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			want := tt.want
			want.baseCred = tt.given
			assert.Equal(want, got)
		})
	}
}
