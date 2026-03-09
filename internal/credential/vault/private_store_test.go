// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_lookupPrivateStore(t *testing.T) {
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
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms, sche)
			require.NoError(err)
			require.NotNil(repo)
			err = RegisterJobs(ctx, sche, rw, rw, kms)
			require.NoError(err)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

			v := NewTestVaultServer(t, WithTestVaultTLS(tt.tls))

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

			_, token := v.CreateToken(t)

			credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token), opts...)
			assert.NoError(err)
			require.NotNil(credStoreIn)
			orig, err := repo.CreateCredentialStore(ctx, credStoreIn)
			assert.NoError(err)
			require.NotNil(orig)

			origLookup, err := repo.LookupCredentialStore(ctx, orig.GetPublicId())
			assert.NoError(err)
			require.NotNil(origLookup)
			assert.NotNil(origLookup.Token())
			assert.Equal(orig.GetPublicId(), origLookup.GetPublicId())

			got, err := repo.lookupClientStore(ctx, orig.GetPublicId())
			assert.NoError(err)
			require.NotNil(got)
			assert.Equal(orig.GetPublicId(), got.GetPublicId())

			assert.Equal(token, string(got.Token))

			if tt.tls == TestClientTLS {
				require.NotNil(got.ClientKey)
				assert.Equal(v.ClientKey, []byte(got.ClientKey))
			}
		})
	}
}
