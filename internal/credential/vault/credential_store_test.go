// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestCredentialStore_New(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	inCert := testClientCert(t, testCaCert(t))
	clientCert, err := NewClientCertificate(ctx, inCert.Cert.Cert, inCert.Cert.Key)
	require.NoError(t, err)
	require.NotNil(t, clientCert)

	type args struct {
		projectId    string
		vaultAddress string
		token        []byte
		opts         []Option
	}

	tests := []struct {
		name          string
		args          args
		want          *CredentialStore
		wantErr       bool
		wantCreateErr bool
	}{
		{
			name: "missing-project-id",
			args: args{
				vaultAddress: "https://vault.consul.service",
				token:        []byte("token"),
			},
			want: &CredentialStore{
				inputToken: []byte("token"),
				CredentialStore: &store.CredentialStore{
					VaultAddress: "https://vault.consul.service",
				},
			},
			wantCreateErr: true,
		},
		{
			name: "missing-vault-address",
			args: args{
				projectId: prj.PublicId,
				token:     []byte("token"),
			},
			want: &CredentialStore{
				inputToken: []byte("token"),
				CredentialStore: &store.CredentialStore{
					ProjectId: prj.PublicId,
				},
			},
			wantCreateErr: true,
		},
		{
			name: "missing-vault-token",
			args: args{
				projectId:    prj.PublicId,
				vaultAddress: "https://vault.consul.service",
			},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ProjectId:    prj.PublicId,
					VaultAddress: "https://vault.consul.service",
				},
			},
			// The DB does not require there be at least 1 token for a store.
			wantCreateErr: false,
		},
		{
			name: "valid-no-options",
			args: args{
				projectId:    prj.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        []byte("token"),
			},
			want: &CredentialStore{
				inputToken: []byte("token"),
				CredentialStore: &store.CredentialStore{
					ProjectId:    prj.PublicId,
					VaultAddress: "https://vault.consul.service",
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				projectId:    prj.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        []byte("token"),
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &CredentialStore{
				inputToken: []byte("token"),
				CredentialStore: &store.CredentialStore{
					ProjectId:    prj.PublicId,
					VaultAddress: "https://vault.consul.service",
					Name:         "test-name",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				projectId:    prj.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        []byte("token"),
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &CredentialStore{
				inputToken: []byte("token"),
				CredentialStore: &store.CredentialStore{
					ProjectId:    prj.PublicId,
					VaultAddress: "https://vault.consul.service",
					Description:  "test-description",
				},
			},
		},
		{
			name: "valid-with-ca-cert",
			args: args{
				projectId:    prj.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        []byte("token"),
				opts: []Option{
					WithCACert([]byte("ca-cert")),
				},
			},
			want: &CredentialStore{
				inputToken: []byte("token"),
				CredentialStore: &store.CredentialStore{
					ProjectId:    prj.PublicId,
					VaultAddress: "https://vault.consul.service",
					CaCert:       []byte("ca-cert"),
				},
			},
		},
		{
			name: "valid-with-namespace",
			args: args{
				projectId:    prj.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        []byte("token"),
				opts: []Option{
					WithNamespace("kazmierczak"),
				},
			},
			want: &CredentialStore{
				inputToken: []byte("token"),
				CredentialStore: &store.CredentialStore{
					ProjectId:    prj.PublicId,
					VaultAddress: "https://vault.consul.service",
					Namespace:    "kazmierczak",
				},
			},
		},
		{
			name: "valid-with-tls-server-name",
			args: args{
				projectId:    prj.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        []byte("token"),
				opts: []Option{
					WithTlsServerName("crews"),
				},
			},
			want: &CredentialStore{
				inputToken: []byte("token"),
				CredentialStore: &store.CredentialStore{
					ProjectId:     prj.PublicId,
					VaultAddress:  "https://vault.consul.service",
					TlsServerName: "crews",
				},
			},
		},
		{
			name: "valid-with-tls-skip-verify",
			args: args{
				projectId:    prj.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        []byte("token"),
				opts: []Option{
					WithTlsSkipVerify(true),
				},
			},
			want: &CredentialStore{
				inputToken: []byte("token"),
				CredentialStore: &store.CredentialStore{
					ProjectId:     prj.PublicId,
					VaultAddress:  "https://vault.consul.service",
					TlsSkipVerify: true,
				},
			},
		},
		{
			name: "valid-with-client-cert",
			args: args{
				projectId:    prj.PublicId,
				vaultAddress: "https://vault.consul.service",
				token:        []byte("token"),
				opts: []Option{
					WithClientCert(clientCert),
				},
			},
			want: &CredentialStore{
				inputToken: []byte("token"),
				clientCert: clientCert,
				CredentialStore: &store.CredentialStore{
					ProjectId:    prj.PublicId,
					VaultAddress: "https://vault.consul.service",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewCredentialStore(tt.args.projectId, tt.args.vaultAddress, tt.args.token, tt.args.opts...)
			if tt.wantErr {
				assert.Error(err)
				require.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)

			assert.Emptyf(got.PublicId, "PublicId set")
			assert.Equal(tt.want, got)
			assert.Empty(cmp.Diff(tt.want, got.clone(), protocmp.Transform()))

			id, err := newCredentialStoreId(ctx)
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
