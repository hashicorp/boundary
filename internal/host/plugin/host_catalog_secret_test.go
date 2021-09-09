package plugin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestHostCatalogSecret_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test", "test")
	cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())

	type args struct {
		catalogId string
		attrs     map[string]interface{}
	}

	tests := []struct {
		name           string
		args           args
		want           *HostCatalogSecret
		wantErr        bool
		wantEncryptErr bool
	}{
		{
			name: "blank-catalog-id",
			args: args{
				catalogId: "",
			},
			want: &HostCatalogSecret{
				HostCatalogSecret: &store.HostCatalogSecret{},
			},
			wantEncryptErr: true,
		},
		{
			name: "no-attributes",
			args: args{
				catalogId: cat.GetPublicId(),
			},
			want: &HostCatalogSecret{
				HostCatalogSecret: &store.HostCatalogSecret{
					CatalogId: cat.GetPublicId(),
				},
			},
			wantEncryptErr: true,
		},
		{
			name: "valid",
			args: args{
				catalogId: cat.GetPublicId(),
				attrs:     map[string]interface{}{"foo": "bar"},
			},
			want: &HostCatalogSecret{
				HostCatalogSecret: &store.HostCatalogSecret{
					CatalogId: cat.GetPublicId(),
					Secret: func() []byte {
						b, err := json.Marshal(map[string]interface{}{"foo": "bar"})
						require.NoError(t, err)
						return b
					}(),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			databaseWrapper, err := kkms.GetWrapper(ctx, prj.PublicId, kms.KeyPurposeDatabase)
			require.NoError(t, err)
			require.NotNil(t, databaseWrapper)

			got, err := newHostCatalogSecret(context.Background(), tt.args.catalogId, tt.args.attrs)
			if tt.wantErr {
				assert.Error(t, err)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)

			assert.Empty(t, got.CtSecret)
			assert.Equal(t, tt.want, got)

			err = got.encrypt(ctx, databaseWrapper)
			if tt.wantEncryptErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NoError(t, got.decrypt(ctx, databaseWrapper))
		})
	}
}

func TestHostCatalogSecret_Custom_Queries(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test", "prefix")
	cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
	databaseWrapper, err := kkms.GetWrapper(ctx, prj.PublicId, kms.KeyPurposeDatabase)

	hcs, err := newHostCatalogSecret(ctx, cat.GetPublicId(), map[string]interface{}{"foo": "bar"})
	require.NoError(t, err)
	assert.NoError(t, hcs.encrypt(ctx, databaseWrapper))
	q, v := hcs.insertQuery()
	_, err = rw.Exec(ctx, q, v)
	assert.NoError(t, err)

	found, err := newHostCatalogSecret(ctx, cat.GetPublicId(), nil)
	assert.NoError(t, rw.LookupWhere(ctx, found, "catalog_id=?", found.GetCatalogId()))
	require.NoError(t, found.decrypt(ctx, databaseWrapper))
	require.NoError(t, hcs.decrypt(ctx, databaseWrapper))
	// update the created/updated time from the original
	hcs.CreateTime, hcs.UpdateTime = found.CreateTime, found.UpdateTime
	assert.Empty(t, cmp.Diff(hcs, found, protocmp.Transform()))

	// Update the secret and see the value updated.
	updated, err := newHostCatalogSecret(ctx, cat.GetPublicId(), map[string]interface{}{"updated": "value"})
	require.NoError(t, err)
	assert.NoError(t, updated.encrypt(ctx, databaseWrapper))
	q, v = updated.insertQuery()
	_, err = rw.Exec(ctx, q, v)
	assert.NoError(t, err)

	assert.NoError(t, rw.LookupWhere(ctx, found, "catalog_id=?", found.GetCatalogId()))
	require.NoError(t, found.decrypt(ctx, databaseWrapper))
	require.NoError(t, updated.decrypt(ctx, databaseWrapper))
	// set the created time to the first and update time from the newly found
	updated.CreateTime, updated.UpdateTime = hcs.CreateTime, found.UpdateTime
	assert.Empty(t, cmp.Diff(updated, found, protocmp.Transform()))

	// Try to delete this secret.
	q, v = updated.deleteQuery()
	_, err = rw.Exec(ctx, q, v)
	assert.NoError(t, err)
	err = rw.LookupWhere(ctx, found, "catalog_id=?", found.GetCatalogId())
	assert.Error(t, err)
	assert.True(t, errors.IsNotFoundError(err))
}
