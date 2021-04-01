package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialStore_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	scope := prj

	type args struct {
		scopeId      string
		vaultAddress string
		token        string
		opts         []Option
	}

	// TODO(mgaffney) 03/2021: Add vault token to tests

	tests := []struct {
		name    string
		args    args
		want    *CredentialStore
		wantErr bool
	}{
		{
			name: "blank-scope-id",
			args: args{
				scopeId: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				scopeId:      scope.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        "token",
			},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ScopeId:      scope.PublicId,
					VaultAddress: "https://vault.consul.service",
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				scopeId:      scope.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        "token",
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ScopeId:      scope.PublicId,
					VaultAddress: "https://vault.consul.service",
					Name:         "test-name",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				scopeId:      scope.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        "token",
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ScopeId:      scope.PublicId,
					VaultAddress: "https://vault.consul.service",
					Description:  "test-description",
				},
			},
		},
		{
			name: "valid-with-ca-cert",
			args: args{
				scopeId:      scope.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        "token",
				opts: []Option{
					WithCACert("ca-cert"),
				},
			},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ScopeId:      scope.PublicId,
					VaultAddress: "https://vault.consul.service",
					CaCert:       "ca-cert",
				},
			},
		},
		{
			name: "valid-with-namespace",
			args: args{
				scopeId:      scope.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        "token",
				opts: []Option{
					WithNamespace("kazmierczak"),
				},
			},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ScopeId:      scope.PublicId,
					VaultAddress: "https://vault.consul.service",
					Namespace:    "kazmierczak",
				},
			},
		},
		{
			name: "valid-with-tls-server-name",
			args: args{
				scopeId:      scope.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        "token",
				opts: []Option{
					WithTlsServerName("crews"),
				},
			},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ScopeId:       scope.PublicId,
					VaultAddress:  "https://vault.consul.service",
					TlsServerName: "crews",
				},
			},
		},
		{
			name: "valid-with-tls-skip-verify",
			args: args{
				scopeId:      scope.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        "token",
				opts: []Option{
					WithTlsSkipVerify(true),
				},
			},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ScopeId:       scope.PublicId,
					VaultAddress:  "https://vault.consul.service",
					TlsSkipVerify: true,
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewCredentialStore(tt.args.scopeId, tt.args.vaultAddress, []byte(tt.args.token), tt.args.opts...)
			if tt.wantErr {
				assert.Error(err)
				require.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)

			assert.Emptyf(got.PublicId, "PublicId set")
			assert.Equal(tt.want, got)

			id, err := newCredentialStoreId()
			assert.NoError(err)

			tt.want.PublicId = id
			got.PublicId = id

			err2 := rw.Create(context.Background(), got)
			assert.NoError(err2)
		})
	}
}
