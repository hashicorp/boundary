// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMethodType(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	assert.IsType(MethodGet, MethodPost)
	assert.IsType(MethodPost, MethodGet)
}

func TestCredentialLibrary_New(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.PublicId, 1)[0]

	type args struct {
		storeId   string
		vaultPath string
		opts      []Option
	}

	tests := []struct {
		name          string
		args          args
		want          *CredentialLibrary
		wantCreateErr bool
	}{
		{
			name: "missing-store-id",
			args: args{
				storeId:   "",
				vaultPath: "vault/path",
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					VaultPath: "vault/path",
				},
			},
			wantCreateErr: true,
		},
		{
			name: "missing-vault-path",
			args: args{
				storeId: cs.PublicId,
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId: cs.PublicId,
				},
			},
			wantCreateErr: true,
		},
		{
			name: "no-options",
			args: args{
				storeId:   cs.PublicId,
				vaultPath: "vault/path",
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:   cs.PublicId,
					VaultPath: "vault/path",
				},
			},
			wantCreateErr: true,
		},
		{
			name: "with-name",
			args: args{
				storeId:   cs.PublicId,
				vaultPath: "vault/path",
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:   cs.PublicId,
					VaultPath: "vault/path",
					Name:      "test-name",
				},
			},
			wantCreateErr: true,
		},
		{
			name: "with-name-method",
			args: args{
				storeId:   cs.PublicId,
				vaultPath: "vault/path",
				opts: []Option{
					WithMethod(MethodGet),
					WithName("test-name"),
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:    cs.PublicId,
					VaultPath:  "vault/path",
					Name:       "test-name",
					HttpMethod: string(MethodGet),
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				storeId:   cs.PublicId,
				vaultPath: "vault/path",
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:     cs.PublicId,
					VaultPath:   "vault/path",
					Description: "test-description",
				},
			},
			wantCreateErr: true,
		},
		{
			name: "valid-with-post-method",
			args: args{
				storeId:   cs.PublicId,
				vaultPath: "vault/path",
				opts: []Option{
					WithMethod(MethodPost),
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:    cs.PublicId,
					HttpMethod: "POST",
					VaultPath:  "vault/path",
				},
			},
		},
		{
			name: "valid-with-post-method-and-body",
			args: args{
				storeId:   cs.PublicId,
				vaultPath: "vault/path",
				opts: []Option{
					WithMethod(MethodPost),
					WithRequestBody([]byte("body")),
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:         cs.PublicId,
					HttpMethod:      "POST",
					VaultPath:       "vault/path",
					HttpRequestBody: []byte("body"),
				},
			},
		},
		{
			name: "get-method-with-body",
			args: args{
				storeId:   cs.PublicId,
				vaultPath: "vault/path",
				opts: []Option{
					WithMethod(MethodGet),
					WithRequestBody([]byte("body")),
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:         cs.PublicId,
					VaultPath:       "vault/path",
					HttpRequestBody: []byte("body"),
					HttpMethod:      "GET",
				},
			},
			wantCreateErr: true,
		},
		{
			name: "minimum-actually-valid",
			args: args{
				storeId:   cs.PublicId,
				vaultPath: "vault/path",
				opts: []Option{
					WithMethod(MethodGet),
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:    cs.PublicId,
					VaultPath:  "vault/path",
					HttpMethod: string(MethodGet),
				},
			},
		},
		{
			name: "credential-type",
			args: args{
				storeId:   cs.PublicId,
				vaultPath: "vault/path",
				opts: []Option{
					WithMethod(MethodGet),
					WithCredentialType(globals.UsernamePasswordCredentialType),
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.PublicId,
					VaultPath:      "vault/path",
					HttpMethod:     string(MethodGet),
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
		},
		{
			name: "credential-type-with-userpass-mapping",
			args: args{
				storeId:   cs.PublicId,
				vaultPath: "vault/path",
				opts: []Option{
					WithMethod(MethodGet),
					WithCredentialType(globals.UsernamePasswordCredentialType),
					WithMappingOverride(NewUsernamePasswordOverride(
						WithOverrideUsernameAttribute("test"),
						WithOverridePasswordAttribute("testpass")),
					),
				},
			},
			want: &CredentialLibrary{
				MappingOverride: NewUsernamePasswordOverride(WithOverrideUsernameAttribute("test"), WithOverridePasswordAttribute("testpass")),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.PublicId,
					VaultPath:      "vault/path",
					HttpMethod:     string(MethodGet),
					CredentialType: string(globals.UsernamePasswordCredentialType),
				},
			},
		},
		{
			name: "credential-type-with-ssh-pk-mapping",
			args: args{
				storeId:   cs.PublicId,
				vaultPath: "vault/path",
				opts: []Option{
					WithMethod(MethodGet),
					WithCredentialType(globals.SshPrivateKeyCredentialType),
					WithMappingOverride(NewSshPrivateKeyOverride(
						WithOverrideUsernameAttribute("test"),
						WithOverridePrivateKeyAttribute("testpk")),
					),
				},
			},
			want: &CredentialLibrary{
				MappingOverride: NewSshPrivateKeyOverride(WithOverrideUsernameAttribute("test"), WithOverridePrivateKeyAttribute("testpk")),
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:        cs.PublicId,
					VaultPath:      "vault/path",
					HttpMethod:     string(MethodGet),
					CredentialType: string(globals.SshPrivateKeyCredentialType),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			got, err := NewCredentialLibrary(tt.args.storeId, tt.args.vaultPath, tt.args.opts...)
			require.NoError(err)
			require.NotNil(got)

			assert.Emptyf(got.PublicId, "PublicId set")
			assert.Equal(tt.want, got)

			switch ct := tt.want.GetCredentialType(); ct {
			case string(globals.UsernamePasswordCredentialType):
				assert.Equal(globals.UsernamePasswordCredentialType, got.CredentialType())
			case string(globals.SshPrivateKeyCredentialType):
				assert.Equal(globals.SshPrivateKeyCredentialType, got.CredentialType())
			case string(globals.UnspecifiedCredentialType), "":
				assert.Equal(globals.UnspecifiedCredentialType, got.CredentialType())
			default:
				assert.Failf("Unknown credential type", "%s", ct)
			}

			id, err := newCredentialLibraryId(ctx)
			assert.NoError(err)

			tt.want.PublicId = id
			got.PublicId = id

			err2 := rw.Create(ctx, got)
			if tt.wantCreateErr {
				assert.Error(err2)
			} else {
				assert.NoError(err2)
			}
		})
	}
}
