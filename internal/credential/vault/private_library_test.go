// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
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
					WithCredentialType(globals.UsernamePasswordCredentialType),
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
					WithCredentialType(globals.UsernamePasswordCredentialType),
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
					WithCredentialType(globals.UsernamePasswordCredentialType),
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
					WithCredentialType(globals.UsernamePasswordCredentialType),
					WithMappingOverride(NewUsernamePasswordOverride(
						WithOverridePasswordAttribute("test-password"),
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
					WithCredentialType(globals.UsernamePasswordDomainCredentialType),
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
					WithCredentialType(globals.UsernamePasswordDomainCredentialType),
					WithMappingOverride(NewUsernamePasswordDomainOverride(
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
					WithCredentialType(globals.UsernamePasswordDomainCredentialType),
					WithMappingOverride(NewUsernamePasswordDomainOverride(
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
					WithCredentialType(globals.UsernamePasswordDomainCredentialType),
					WithMappingOverride(NewUsernamePasswordDomainOverride(
						WithOverrideDomainAttribute("test-domain"),
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
					WithCredentialType(globals.UsernamePasswordDomainCredentialType),
					WithMappingOverride(NewUsernamePasswordDomainOverride(
						WithOverridePasswordAttribute("test-password"),
						WithOverrideDomainAttribute("test-domain"),
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
					WithCredentialType(globals.UsernamePasswordDomainCredentialType),
					WithMappingOverride(NewUsernamePasswordDomainOverride(
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
					WithCredentialType(globals.UsernamePasswordDomainCredentialType),
					WithMappingOverride(NewUsernamePasswordDomainOverride(
						WithOverrideUsernameAttribute("test-username"),
						WithOverrideDomainAttribute("test-domain"),
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
					WithCredentialType(globals.UsernamePasswordDomainCredentialType),
					WithMappingOverride(NewUsernamePasswordDomainOverride(
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
					WithCredentialType(globals.UsernamePasswordDomainCredentialType),
					WithMappingOverride(NewUsernamePasswordDomainOverride(
						WithOverrideUsernameAttribute("test-username"),
						WithOverridePasswordAttribute("test-password"),
						WithOverrideDomainAttribute("test-domain"),
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
					WithCredentialType(globals.PasswordCredentialType),
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
					WithCredentialType(globals.PasswordCredentialType),
					WithMappingOverride(NewPasswordOverride(
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
					WithCredentialType(globals.SshPrivateKeyCredentialType),
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
					WithCredentialType(globals.SshPrivateKeyCredentialType),
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
					WithCredentialType(globals.SshPrivateKeyCredentialType),
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
					WithCredentialType(globals.SshPrivateKeyCredentialType),
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
					WithCredentialType(globals.SshPrivateKeyCredentialType),
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
					case *UsernamePasswordDomainOverride:
						assert.Equal(w.UsernameAttribute, got.UsernameAttribute)
						assert.Equal(w.PasswordAttribute, got.PasswordAttribute)
						assert.Equal(w.DomainAttribute, got.DomainAttribute)
					case *PasswordOverride:
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
					CredType: string(globals.UnspecifiedCredentialType),
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-username-default-password-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordCredentialType),
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
					CredType: string(globals.UsernamePasswordCredentialType),
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
					CredType: string(globals.UsernamePasswordCredentialType),
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
					CredType:          string(globals.UsernamePasswordCredentialType),
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
					CredType:          string(globals.UsernamePasswordCredentialType),
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
					CredType:          string(globals.UsernamePasswordCredentialType),
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
					CredType:          string(globals.UsernamePasswordCredentialType),
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
					CredType:          string(globals.UsernamePasswordCredentialType),
					PasswordAttribute: "missing-password",
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
					CredType: string(globals.UsernamePasswordCredentialType),
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
					CredType: string(globals.UsernamePasswordCredentialType),
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
					CredType: string(globals.UsernamePasswordCredentialType),
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
			name: "invalid-kv2-no-password-default-username-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordCredentialType),
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
					CredType: string(globals.UsernamePasswordCredentialType),
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
					CredType: string(globals.UsernamePasswordCredentialType),
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
					CredType: string(globals.UsernamePasswordCredentialType),
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
					CredType: string(globals.UsernamePasswordCredentialType),
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
					CredType:          string(globals.UsernamePasswordCredentialType),
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
					CredType:          string(globals.UsernamePasswordCredentialType),
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
					CredType:          string(globals.UsernamePasswordCredentialType),
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

func TestBaseToUsrPassDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		given   *baseCred
		want    *usrPassDomainCred
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
			name: "library-not-username-password-domain-type",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UnspecifiedCredentialType),
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-username-default-password-no-domain-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordDomainCredentialType),
				},
				secretData: map[string]any{
					"password": "my-password",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-no-password-default-username-no-domain-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordDomainCredentialType),
				},
				secretData: map[string]any{
					"username": "my-username",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-no-password-no-username-default-domain-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordDomainCredentialType),
				},
				secretData: map[string]any{
					"domain": "my-domain",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "valid-default-attributes",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordDomainCredentialType),
				},
				secretData: map[string]any{
					"username": "my-username",
					"password": "my-password",
					"domain":   "my-domain",
				},
			},
			want: &usrPassDomainCred{
				username: "my-username",
				password: credential.Password("my-password"),
				domain:   "my-domain",
			},
		},
		{
			name: "valid-override-attributes",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(globals.UsernamePasswordDomainCredentialType),
					UsernameAttribute: "test-username",
					PasswordAttribute: "test-password",
					DomainAttribute:   "test-domain",
				},
				secretData: map[string]any{
					"username":      "default-username",
					"password":      "default-password",
					"domain":        "default-domain",
					"test-username": "override-username",
					"test-password": "override-password",
					"test-domain":   "override-domain",
				},
			},
			want: &usrPassDomainCred{
				username: "override-username",
				password: credential.Password("override-password"),
				domain:   "override-domain",
			},
		},
		{
			name: "valid-default-username-override-password-override-domain",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(globals.UsernamePasswordDomainCredentialType),
					PasswordAttribute: "test-password",
					DomainAttribute:   "test-domain",
				},
				secretData: map[string]any{
					"username":      "default-username",
					"password":      "default-password",
					"domain":        "default-domain",
					"test-username": "override-username",
					"test-password": "override-password",
					"test-domain":   "override-domain",
				},
			},
			want: &usrPassDomainCred{
				username: "default-username",
				password: credential.Password("override-password"),
				domain:   "override-domain",
			},
		},
		{
			name: "valid-override-username-default-password-default-domain",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(globals.UsernamePasswordDomainCredentialType),
					UsernameAttribute: "test-username",
				},
				secretData: map[string]any{
					"username":      "default-username",
					"password":      "default-password",
					"domain":        "default-domain",
					"test-username": "override-username",
					"test-password": "override-password",
					"test-domain":   "override-domain",
				},
			},
			want: &usrPassDomainCred{
				username: "override-username",
				password: credential.Password("default-password"),
				domain:   "default-domain",
			},
		},
		{
			name: "valid-default-username-default-password-override-domain",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:        string(globals.UsernamePasswordDomainCredentialType),
					DomainAttribute: "test-domain",
				},
				secretData: map[string]any{
					"username":      "default-username",
					"password":      "default-password",
					"domain":        "default-domain",
					"test-username": "override-username",
					"test-password": "override-password",
					"test-domain":   "override-domain",
				},
			},
			want: &usrPassDomainCred{
				username: "default-username",
				password: credential.Password("default-password"),
				domain:   "override-domain",
			},
		},
		{
			name: "invalid-username-override",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(globals.UsernamePasswordDomainCredentialType),
					UsernameAttribute: "missing-username",
				},
				secretData: map[string]any{
					"username":      "default-username",
					"password":      "default-password",
					"domain":        "default-domain",
					"test-username": "override-username",
					"test-password": "override-password",
					"test-domain":   "override-domain",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-password-override",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(globals.UsernamePasswordDomainCredentialType),
					PasswordAttribute: "missing-password",
				},
				secretData: map[string]any{
					"username":      "default-username",
					"password":      "default-password",
					"domain":        "default-domain",
					"test-username": "override-username",
					"test-password": "override-password",
					"test-domain":   "override-domain",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-domain-override",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:        string(globals.UsernamePasswordDomainCredentialType),
					DomainAttribute: "missing-domain",
				},
				secretData: map[string]any{
					"username":      "default-username",
					"password":      "default-password",
					"domain":        "default-domain",
					"test-username": "override-username",
					"test-password": "override-password",
					"test-domain":   "override-domain",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-metadata-field",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordDomainCredentialType),
				},
				secretData: map[string]any{
					"data": map[string]any{
						"username": "my-username",
						"password": "my-password",
						"domain":   "my-domain",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-data-field",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordDomainCredentialType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-username-default-password-default-domain-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordDomainCredentialType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"password": "my-password",
						"domain":   "my-domain",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-default-username-no-password-default-domainattribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordDomainCredentialType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username": "my-username",
						"domain":   "my-domain",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-default-username-default-password-no-domainattribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordDomainCredentialType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
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
					CredType: string(globals.UsernamePasswordDomainCredentialType),
				},
				secretData: map[string]any{
					"metadata": "hello",
					"data": map[string]any{
						"username": "my-username",
						"password": "my-password",
						"domain":   "my-domain",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-invalid-metadata-type",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordDomainCredentialType),
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
					CredType: string(globals.UsernamePasswordDomainCredentialType),
				},
				secretData: map[string]any{
					"bad-field": "hello",
					"metadata":  map[string]any{},
					"data": map[string]any{
						"username": "my-username",
						"password": "my-password",
						"domain":   "my-domain",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "valid-kv2-default-attributes",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UsernamePasswordDomainCredentialType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username": "my-username",
						"password": "my-password",
						"domain":   "my-domain",
					},
				},
			},
			want: &usrPassDomainCred{
				username: "my-username",
				password: credential.Password("my-password"),
				domain:   "my-domain",
			},
		},
		{
			name: "valid-kv2-override-attributes",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(globals.UsernamePasswordDomainCredentialType),
					UsernameAttribute: "test-username",
					PasswordAttribute: "test-password",
					DomainAttribute:   "test-domain",
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username":      "default-username",
						"password":      "default-password",
						"domain":        "default-domain",
						"test-username": "override-username",
						"test-password": "override-password",
						"test-domain":   "override-domain",
					},
				},
			},
			want: &usrPassDomainCred{
				username: "override-username",
				password: credential.Password("override-password"),
				domain:   "override-domain",
			},
		},
		{
			name: "valid-kv2-default-username-override-password-default-domain",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(globals.UsernamePasswordDomainCredentialType),
					PasswordAttribute: "test-password",
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username":      "default-username",
						"password":      "default-password",
						"domain":        "default-domain",
						"test-username": "override-username",
						"test-password": "override-password",
						"test-domain":   "override-domain",
					},
				},
			},
			want: &usrPassDomainCred{
				username: "default-username",
				password: credential.Password("override-password"),
				domain:   "default-domain",
			},
		},
		{
			name: "valid-kv2-override-username-default-password-default-domain",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(globals.UsernamePasswordDomainCredentialType),
					UsernameAttribute: "test-username",
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username":      "default-username",
						"password":      "default-password",
						"domain":        "default-domain",
						"test-username": "override-username",
						"test-password": "override-password",
						"test-domain":   "override-domain",
					},
				},
			},
			want: &usrPassDomainCred{
				username: "override-username",
				password: credential.Password("default-password"),
				domain:   "default-domain",
			},
		},
		{
			name: "valid-kv2-default-username-default-password-override-domain",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:        string(globals.UsernamePasswordDomainCredentialType),
					DomainAttribute: "test-domain",
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username":      "default-username",
						"password":      "default-password",
						"domain":        "default-domain",
						"test-username": "override-username",
						"test-password": "override-password",
						"test-domain":   "override-domain",
					},
				},
			},
			want: &usrPassDomainCred{
				username: "default-username",
				password: credential.Password("default-password"),
				domain:   "override-domain",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := baseToUsrPassDomain(context.Background(), tt.given)
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

func TestBaseToPass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		given   *baseCred
		want    *passCred
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
			name: "library-not-password-type",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.UnspecifiedCredentialType),
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-password-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.PasswordCredentialType),
				},
				secretData: map[string]any{},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "valid-default-attributes",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.PasswordCredentialType),
				},
				secretData: map[string]any{
					"password": "my-password",
				},
			},
			want: &passCred{
				password: credential.Password("my-password"),
			},
		},
		{
			name: "valid-override-attributes",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(globals.PasswordCredentialType),
					PasswordAttribute: "test-password",
				},
				secretData: map[string]any{
					"password":      "default-password",
					"test-password": "override-password",
				},
			},
			want: &passCred{
				password: credential.Password("override-password"),
			},
		},
		{
			name: "invalid-password-override",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(globals.PasswordCredentialType),
					PasswordAttribute: "missing-password",
				},
				secretData: map[string]any{
					"password":      "default-password",
					"test-password": "override-password",
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-no-metadata-field",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.PasswordCredentialType),
				},
				secretData: map[string]any{
					"data": map[string]any{
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
					CredType: string(globals.PasswordCredentialType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "invalid-kv2-invalid-metadata-type",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.PasswordCredentialType),
				},
				secretData: map[string]any{
					"metadata": "hello",
					"data": map[string]any{
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
					CredType: string(globals.PasswordCredentialType),
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
					CredType: string(globals.PasswordCredentialType),
				},
				secretData: map[string]any{
					"bad-field": "hello",
					"metadata":  map[string]any{},
					"data": map[string]any{
						"password": "my-password",
					},
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name: "valid-kv2-default-password-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.PasswordCredentialType),
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"password": "my-password",
					},
				},
			},
			want: &passCred{
				password: credential.Password("my-password"),
			},
		},
		{
			name: "valid-kv2-override-password-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType:          string(globals.PasswordCredentialType),
					PasswordAttribute: "test-password",
				},
				secretData: map[string]any{
					"metadata": map[string]any{},
					"data": map[string]any{
						"password":      "default-password",
						"test-password": "override-password",
					},
				},
			},
			want: &passCred{
				password: credential.Password("override-password"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := baseToPass(context.Background(), tt.given)
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
					CredType: string(globals.UnspecifiedCredentialType),
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-username-default-pk-attribute",
			given: &baseCred{
				lib: &genericIssuingCredentialLibrary{
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType:            string(globals.SshPrivateKeyCredentialType),
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
					CredType:                      string(globals.SshPrivateKeyCredentialType),
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
					CredType:            string(globals.SshPrivateKeyCredentialType),
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
					CredType:          string(globals.SshPrivateKeyCredentialType),
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
					CredType:          string(globals.SshPrivateKeyCredentialType),
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
					CredType:          string(globals.SshPrivateKeyCredentialType),
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
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType: string(globals.SshPrivateKeyCredentialType),
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
					CredType:            string(globals.SshPrivateKeyCredentialType),
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
					CredType:                      string(globals.SshPrivateKeyCredentialType),
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
					CredType:            string(globals.SshPrivateKeyCredentialType),
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
					CredType:          string(globals.SshPrivateKeyCredentialType),
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

func TestRepository_ldapCertIssuingCredentialLibrary_retrieveCredential(t *testing.T) {
	// Create Vault server
	v := NewTestVaultServer(t, WithTestVaultTLS(TestNoTLS), WithVaultVersion("1.20.0"), WithDockerNetwork(true))
	require.NotNil(t, v)

	vc := v.client(t).cl
	mounts, err := vc.Sys().ListMounts()
	require.NoError(t, err)
	require.NotEmpty(t, mounts)

	// Create OpenLDAP server and mount Vault LDAP secrets engine.
	_ = MountLdapServer(t, v)

	// Create and setup Boundary DB
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)

	sche := scheduler.TestScheduler(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)
	repo, err := NewRepository(t.Context(), rw, rw, kms, sche)
	require.NoError(t, err)
	require.NotNil(t, repo)

	sec, token := v.CreateToken(t, WithPolicies([]string{"default", "boundary-controller", "ldap"}), WithTokenPeriod(time.Hour))
	require.NotNil(t, sec)
	require.NotEmpty(t, token)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), v.Addr, token, sec.Auth.Accessor)

	tests := []struct {
		name              string
		vaultPath         string
		expStaticUsername string
		expDomain         string
		expDynamicCred    bool
		expErr            bool
		expErrMsg         string
	}{
		{
			name:      "doesntExistStaticCred",
			vaultPath: "ldap/static-cred/doesntexist",
			expErr:    true,
			expErrMsg: "unknown role:",
		},
		{
			name:      "doesntExistDynamicCred",
			vaultPath: "ldap/creds/doesntexist",
			expErr:    true,
			expErrMsg: "vault secret is empty",
		},
		{
			name:              "staticCred",
			vaultPath:         "ldap/static-cred/einstein",
			expStaticUsername: "einstein",
			expDomain:         "example.org",
		},
		{
			name:              "staticCredHierarchical",
			vaultPath:         "ldap/static-cred/myorg/myproject/newton",
			expStaticUsername: "newton",
			expDomain:         "example.org",
		},
		{
			name:           "dynamicCred",
			vaultPath:      "ldap/creds/scientists",
			expDynamicCred: true,
			expDomain:      "example.org",
		},
		{
			name:           "dynamicCredHierarchical",
			vaultPath:      "ldap/creds/myorg/myproject/scientists",
			expDynamicCred: true,
			expDomain:      "example.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lib, err := NewLdapCredentialLibrary(cs.GetPublicId(), tt.vaultPath)
			require.NoError(t, err)
			require.NotNil(t, lib)
			lib.PublicId, err = newLdapCredentialLibraryId(t.Context())
			require.NoError(t, err)

			_, err = rw.DoTx(t.Context(), db.StdRetryCnt, db.ExpBackoff{},
				func(_ db.Reader, iw db.Writer) error {
					return iw.Create(t.Context(), lib)
				},
			)
			require.NoError(t, err)

			libs, err := repo.getIssueCredLibraries(t.Context(), []credential.Request{{
				SourceId: lib.GetPublicId(),
			}})
			require.NoError(t, err)
			require.Len(t, libs, 1)

			cred, err := libs[0].retrieveCredential(t.Context(), "TestLdapRetrieveCredential")
			if tt.expErr {
				require.ErrorContains(t, err, tt.expErrMsg)
				return
			}
			require.NoError(t, err)

			require.IsType(t, &usrPassDomainCred{}, cred)
			credUpd := cred.(*usrPassDomainCred)
			require.NotEmpty(t, credUpd.baseCred)
			require.NotEmpty(t, credUpd.getCredential())
			require.EqualValues(t, libs[0], credUpd.lib)
			require.NotEmpty(t, credUpd.secretData)
			require.Contains(t, credUpd.secretData, "username")
			require.Contains(t, credUpd.secretData, "password")

			require.EqualValues(t, credUpd.secretData["password"], credUpd.Password())
			require.EqualValues(t, tt.expDomain, credUpd.Domain())
			if !tt.expDynamicCred {
				require.EqualValues(t, credUpd.secretData["username"], credUpd.Username())
				require.EqualValues(t, tt.expStaticUsername, credUpd.Username())
				require.False(t, credUpd.GetIsRenewable())
			} else {
				require.EqualValues(t, credUpd.secretData["username"], credUpd.Username())
				require.Contains(t, credUpd.Username(), "b_token-TestRepository-ldapCertIssuingCredentialLibrary-retrieveCredential_")
				require.True(t, credUpd.GetIsRenewable())
			}
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
		keyId      string
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
			name:     "vault issue ec(256) cert with template key ID",
			username: "username-7-because-789",
			keyId:    `{{truncateFrom .Account.Email "@"}}`,
			expected: map[string]any{
				"key_id":           "rise-of-the-template",
				"valid_principals": []string{"username-7-because-789"},
			},
			vaulthPath: "ssh/issue/boundary",
			opts:       []Option{WithKeyType(KeyTypeEcdsa), WithKeyBits(256)},
			retOpts:    []credential.Option{credential.WithTemplateData(template.Data{Account: template.Account{Email: util.Pointer("rise-of-the-template@foobar.com")}})},
		},
		{
			name:     "vault issue ec(256) cert with coalesce username",
			username: `{{coalesce .Account.LoginName .Account.Name .Account.Email}}`,
			expected: map[string]any{
				"username":         "name-that-name",
				"valid_principals": []string{"name-that-name"},
			},
			vaulthPath: "ssh/issue/boundary",
			opts:       []Option{WithKeyType(KeyTypeEcdsa), WithKeyBits(256)},
			retOpts:    []credential.Option{credential.WithTemplateData(template.Data{Account: template.Account{Name: util.Pointer("name-that-name"), LoginName: util.Pointer(""), Email: util.Pointer("rise-of-the-template@foobar.com")}})},
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

func TestExtractDomainFromDn(t *testing.T) {
	tests := []struct {
		name              string
		inDn              string
		expDomain         string
		expErr            bool
		expErrMsgContains string
	}{
		{
			name:              "emptyString",
			inDn:              "",
			expErr:            true,
			expErrMsgContains: "empty DN",
		},
		{
			name:              "notADn",
			inDn:              "a string that isn't really a DN",
			expErr:            true,
			expErrMsgContains: "failed to parse DN:",
		},
		{
			name:      "validDn",
			inDn:      "dc=domain,dc=tld",
			expDomain: "domain.tld",
		},
		{
			name:      "validDnSpaces",
			inDn:      "dc = domain , dc = tld",
			expDomain: "domain.tld",
		},
		{
			name:      "validDnCaps",
			inDn:      "DC=DOMAIN,DC=TLD",
			expDomain: "DOMAIN.TLD",
		},
		{
			name:      "validDnOid",
			inDn:      "0.9.2342.19200300.100.1.25=Domain,0.9.2342.19200300.100.1.25=Tld",
			expDomain: "Domain.Tld",
		},
		{
			name:      "validDnOidMixed",
			inDn:      "dc=sub1,0.9.2342.19200300.100.1.25=Domain,dc=Tld",
			expDomain: "sub1.Domain.Tld",
		},
		{
			name:      "validDnWithCn",
			inDn:      "CN=My User,CN=admin,DC=mycorp,DC=domain,DC=TLD",
			expDomain: "mycorp.domain.TLD",
		},
		{
			name:      "validDnWithEscapeChars",
			inDn:      `CN=mycn,OU=HashiCorp\, an IBM Company,DC=domain,DC=TLD`,
			expDomain: "domain.TLD",
		},
		{
			name:      "validDnWithEscapeChars2",
			inDn:      `CN=Before\0DAfter,OU=HashiCorp,DC=domain,DC=TLD`,
			expDomain: "domain.TLD",
		},
		{
			name:      "validDnWithSubdomains",
			inDn:      `dc=foo,dc=bAR,dc=BAZ,dc=domain,dc=Tld`,
			expDomain: "foo.bAR.BAZ.domain.Tld",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, err := extractDomainFromDn(tt.inDn)
			if tt.expErr {
				require.ErrorContains(t, err, tt.expErrMsgContains)
				require.Empty(t, domain)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expDomain, domain)
		})
	}
}
