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
		opts         []Option
	}

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
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewCredentialStore(tt.args.scopeId, tt.args.vaultAddress, tt.args.opts...)
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
