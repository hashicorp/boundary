// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/internal/util/template"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
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

			repo, err := NewRepository(ctx, rw, rw, kms, sche)
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
				clientCert, err := NewClientCertificate(ctx, v.ClientCert, v.ClientKey)
				require.NoError(err)
				opts = append(opts, WithClientCert(clientCert))
			}

			_, token := v.CreateToken(t, WithTokenPeriod(time.Hour))

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

			gotLibs, err := repo.getIssueCredLibraries(ctx, requests)
			assert.NoError(err)
			require.NotNil(gotLibs)
			assert.Len(gotLibs, len(libs))

			for _, gotLib := range gotLibs {
				got, ok := gotLib.(*genericIssuingCredentialLibrary)
				require.True(ok)

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
	ctx := context.Background()

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
			mapper, err := newMapper(ctx, tt.args.requests)
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
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UnspecifiedType),
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-username-default-password-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]any{
					"password": "my-password",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-no-password-default-username-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]any{
					"username": "my-username",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "valid-default-attributes",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(credential.UsernamePasswordType),
					UsernameAttribute: "test-username",
					PasswordAttribute: "test-password",
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(credential.UsernamePasswordType),
					PasswordAttribute: "test-password",
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(credential.UsernamePasswordType),
					UsernameAttribute: "test-username",
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(credential.UsernamePasswordType),
					UsernameAttribute: "missing-username",
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(credential.UsernamePasswordType),
					UsernameAttribute: "missing-password",
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]any{
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-username-default-password-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"password": "my-password",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-passsword-default-username-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username": "my-username",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-invalid-metadata-type",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]any{
					"metadata": "hello",
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data":     "hello",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-additional-field",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]any{
					"bad-field": "hello",
					"metadata":  map[string]any{},
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UsernamePasswordType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(credential.UsernamePasswordType),
					UsernameAttribute: "test-username",
					PasswordAttribute: "test-password",
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(credential.UsernamePasswordType),
					PasswordAttribute: "test-password",
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(credential.UsernamePasswordType),
					UsernameAttribute: "test-username",
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.UnspecifiedType),
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-username-default-pk-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
					"private_key": "my-pk",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-no-pk-default-username-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
					"username": "my-username",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "valid-default-attributes",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:            string(credential.SshPrivateKeyType),
					UsernameAttribute:   "test-username",
					PrivateKeyAttribute: "test-pk",
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:                      string(credential.SshPrivateKeyType),
					UsernameAttribute:             "test-username",
					PrivateKeyAttribute:           "test-pk",
					PrivateKeyPassphraseAttribute: "test-pass",
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:            string(credential.SshPrivateKeyType),
					PrivateKeyAttribute: "test-pk",
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(credential.SshPrivateKeyType),
					UsernameAttribute: "test-username",
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(credential.SshPrivateKeyType),
					UsernameAttribute: "missing-username",
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(credential.SshPrivateKeyType),
					UsernameAttribute: "missing-pk",
				},
				secretData: map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-username-default-pk-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"private_key": "default-pk",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-pk-default-username-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username": "default-username",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-invalid-metadata-type",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
					"metadata": "hello",
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data":     "hello",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-additional-field",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
					"bad-field": "hello",
					"metadata":  map[string]any{},
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType: string(credential.SshPrivateKeyType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:            string(credential.SshPrivateKeyType),
					UsernameAttribute:   "test-username",
					PrivateKeyAttribute: "test-pk",
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:                      string(credential.SshPrivateKeyType),
					UsernameAttribute:             "test-username",
					PrivateKeyAttribute:           "test-pk",
					PrivateKeyPassphraseAttribute: "test-pass",
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:            string(credential.SshPrivateKeyType),
					PrivateKeyAttribute: "test-pk",
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
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
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(credential.SshPrivateKeyType),
					UsernameAttribute: "test-username",
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
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

func TestRepository_sshCertIssuingCredentialLibrary_retrieveCredential(t *testing.T) {
	t.Parallel()

	// create test vault server
	v := NewTestVaultServer(t, WithTestVaultTLS(TestNoTLS), WithVaultVersion("1.12.2"))
	require.NotNil(t, v)

	vc := v.client(t).cl
	mounts, err := vc.Sys().ListMounts()
	assert.NoError(t, err)
	require.NotEmpty(t, mounts)
	beforeCount := len(mounts)

	// enable ssh secrets engine
	v.MountSSH(t, WithAllowedExtension("permit-pty"))
	mounts, err = vc.Sys().ListMounts()
	fmt.Printf("mounts: %#v\n", mounts)
	assert.NoError(t, err)
	require.NotEmpty(t, mounts)
	afterCount := len(mounts)
	assert.Greater(t, afterCount, beforeCount)

	// create and setup db
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	sec, token := v.CreateToken(t, WithPolicies([]string{"default", "boundary-controller", "ssh"}), WithTokenPeriod(time.Hour))

	sche := scheduler.TestScheduler(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(t, err)
	require.NotNil(t, repo)

	cs := TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), v.Addr, token, sec.Auth.Accessor)

	tests := []struct {
		name       string
		username   string
		vaulthPath string
		opts       []Option
		retOpts    []credential.Option
		expected   map[string]any
	}{
		{
			name:       "vault sign boundary ed25519 key",
			username:   "username",
			vaulthPath: "ssh/sign/boundary",
			opts:       []Option{WithKeyType(KeyTypeEd25519)},
		},
		{
			name:       "vault sign boundary rsa(4096) key",
			username:   "username-2-electric-boogaloo",
			vaulthPath: "ssh/sign/boundary",
			opts:       []Option{WithKeyType(KeyTypeRsa), WithKeyBits(4096)},
		},
		{
			name:       "vault sign boundary ec(521) key",
			username:   "username-3-the-namening",
			vaulthPath: "ssh/sign/boundary",
			opts:       []Option{WithKeyType(KeyTypeEcdsa), WithKeyBits(521)},
		},
		{
			name:       "vault issue ed25519 cert",
			username:   "username-4-revengeance",
			vaulthPath: "ssh/issue/boundary",
			opts:       []Option{WithKeyType(KeyTypeEd25519)},
		},
		{
			name:       "vault issue rsa(4096) cert",
			username:   "username-5-this-time-its-personal",
			vaulthPath: "ssh/issue/boundary",
			opts:       []Option{WithKeyType(KeyTypeRsa), WithKeyBits(4096)},
		},
		{
			name:       "vault issue ec(521) cert",
			username:   "username-6-the-holiday-episode",
			vaulthPath: "ssh/issue/boundary",
			opts:       []Option{WithKeyType(KeyTypeEcdsa), WithKeyBits(521)},
		},
		{
			name:       "vault issue rsa(2048) cert with critical options and extensions",
			username:   "username-7-because-789",
			vaulthPath: "ssh/issue/boundary",
			opts:       []Option{WithKeyType(KeyTypeRsa), WithKeyBits(2048), WithCriticalOptions("{ \"force-commnad\": \"/bin/some-script\" }"), WithExtensions("{ \"permit-pty\": \"\" }")},
		},
		{
			name:       "vault sign boundary rsa(3072) key with critical options and extensions",
			username:   "username-7-because-789",
			vaulthPath: "ssh/sign/boundary",
			opts:       []Option{WithKeyType(KeyTypeRsa), WithKeyBits(3072), WithCriticalOptions("{ \"force-commnad\": \"/bin/some-script\" }"), WithExtensions("{ \"permit-pty\": \"\" }")},
		},
		{
			name:     "vault issue ec(256) cert with template username",
			username: "username-8-{{ .User.Name }}",
			expected: map[string]any{
				"username":         "username-8-revenge-of-the-template",
				"valid_principals": []string{"username-8-revenge-of-the-template"},
			},
			vaulthPath: "ssh/issue/boundary",
			opts:       []Option{WithKeyType(KeyTypeEcdsa), WithKeyBits(256)},
			retOpts:    []credential.Option{credential.WithTemplateData(template.Data{User: template.User{Name: util.Pointer("revenge-of-the-template")}})},
		},
		{
			name:     "vault issue ec(384) cert with disallowed extension",
			username: "username-10-because-789",
			expected: map[string]any{
				"error": "extensions [permit-port-forwarding] are not on allowed list",
			},
			vaulthPath: "ssh/issue/boundary",
			opts:       []Option{WithKeyType(KeyTypeEcdsa), WithKeyBits(384), WithExtensions("{ \"permit-port-forwarding\": \"\" }")},
		},
		{
			name:     "vault issue ed25519 cert with additional valid principals",
			username: "no-one-expects-the-spanish-inquisition",
			expected: map[string]any{
				"valid_principals": []string{"no-one-expects-the-spanish-inquisition", "test-principal"},
			},
			vaulthPath: "ssh/issue/boundary",
			opts:       []Option{WithKeyType(KeyTypeEd25519), WithAdditionalValidPrincipals([]string{"test-principal"})},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			// create ssh library
			lib, err := NewSSHCertificateCredentialLibrary(cs.GetPublicId(), tt.vaulthPath, tt.username, tt.opts...)
			require.NoError(err)
			require.NotNil(lib)
			lib.PublicId, err = newSSHCertificateCredentialLibraryId(ctx)
			require.NoError(err)

			_, err = rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
				func(_ db.Reader, iw db.Writer) error {
					return iw.Create(ctx, lib)
				},
			)
			require.NoError(err)

			req := credential.Request{
				SourceId: lib.GetPublicId(),
				Purpose:  "doesn't matter",
			}

			libs, err := repo.getIssueCredLibraries(ctx, []credential.Request{req})
			require.NoError(err)
			require.NotEmpty(libs)
			require.Equal(1, len(libs))

			cred, err := libs[0].retrieveCredential(ctx, "op", tt.retOpts...)
			if retErr, ok := tt.expected["error"]; ok {
				require.ErrorContains(err, retErr.(string))
				return // retrieveCredential failed (as expected) don't do the rest of the checks
			}
			require.NoError(err)

			sshCert, ok := cred.(*sshCertCred)
			require.True(ok)

			if usr, ok := tt.expected["username"]; ok {
				require.Equal(usr, sshCert.username)
			}

			// TODO: somehow check that the ssh cert matches the private key
			// for now, manually check that private key and cert match and that sign/issue both return correct formats
			fmt.Printf("test: %s\npriv:\n%s\ncert:\n%s\n", tt.name, string(sshCert.privateKey), string(sshCert.certificate))
			pub, _, _, _, err := ssh.ParseAuthorizedKey(sshCert.certificate)
			require.NoError(err)
			priv, err := ssh.ParsePrivateKey(sshCert.privateKey)
			require.NoError(err)
			cert, ok := pub.(*ssh.Certificate)
			require.True(ok)

			// ensure both keys are the same type
			require.Equal(priv.PublicKey().Type(), cert.Key.Type())

			if vp, ok := tt.expected["valid_principals"]; ok {
				require.Equal(vp, cert.ValidPrincipals)
			}

			// ensure credential matches expected SshCertificate
			_, ok = cred.(credential.SshCertificate)
			require.True(ok)
		})
	}
}
