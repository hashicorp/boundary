package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestHostCatalogSecret_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())

	type args struct {
		catalogId string
		ttl       int32
		attrs     *structpb.Struct
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
				ttl:       -1,
			},
			want: &HostCatalogSecret{
				HostCatalogSecret: &store.HostCatalogSecret{
					RefreshAtTime: nil,
				},
			},
			wantEncryptErr: true,
		},
		{
			name: "no-attributes",
			args: args{
				catalogId: cat.GetPublicId(),
				ttl:       -1,
			},
			want: &HostCatalogSecret{
				HostCatalogSecret: &store.HostCatalogSecret{
					CatalogId:     cat.GetPublicId(),
					RefreshAtTime: nil,
				},
			},
			wantEncryptErr: true,
		},
		{
			name: "valid",
			args: args{
				catalogId: cat.GetPublicId(),
				ttl:       42,
				attrs: func() *structpb.Struct {
					st, err := structpb.NewStruct(map[string]interface{}{"foo": "bar"})
					require.NoError(t, err)
					return st
				}(),
			},
			want: &HostCatalogSecret{
				HostCatalogSecret: &store.HostCatalogSecret{
					CatalogId:     cat.GetPublicId(),
					RefreshAtTime: timestamp.New(time.Now().Add(time.Second * time.Duration(42))),
					Secret: func() []byte {
						st, err := structpb.NewStruct(map[string]interface{}{"foo": "bar"})
						require.NoError(t, err)
						b, err := proto.Marshal(st)
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

			got, err := newHostCatalogSecret(context.Background(), tt.args.catalogId, tt.args.ttl, tt.args.attrs)
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

func TestHostCatalogSecret_Create_Upsert_Update_Delete(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
	ctx := context.Background()

	secret, err := newHostCatalogSecret(ctx, cat.GetPublicId(), 0, mustStruct(map[string]interface{}{
		"foo": "bar",
	}))
	require.NoError(t, err)
	require.NotNil(t, secret)
	require.Empty(t, secret.CtSecret)

	databaseWrapper, err := kkms.GetWrapper(ctx, prj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	require.NotNil(t, databaseWrapper)
	require.NoError(t, secret.encrypt(ctx, databaseWrapper))

	// Create
	w := db.New(conn)
	require.NoError(t, w.Create(ctx, secret))

	// Upsert
	newStructUpsert := mustMarshal(map[string]interface{}{
		"baz": "qux",
	})
	newSecretUpsert := secret.clone()
	newSecretUpsert.RefreshAtTime = timestamp.New(time.Now().Add(time.Second * 30))
	newSecretUpsert.Secret = newStructUpsert
	require.NoError(t, newSecretUpsert.encrypt(ctx, databaseWrapper))
	require.NoError(t, w.Create(ctx, newSecretUpsert, db.WithOnConflict(&db.OnConflict{
		Target: db.Columns{"catalog_id"},
		Action: db.SetColumns([]string{"secret", "key_id", "refresh_at_time"}),
	})))
	found := &HostCatalogSecret{
		HostCatalogSecret: &store.HostCatalogSecret{
			CatalogId: cat.GetPublicId(),
		},
	}
	require.NoError(t, w.LookupById(ctx, found))
	assert.Empty(t, cmp.Diff(newSecretUpsert.HostCatalogSecret, found.HostCatalogSecret, protocmp.Transform()))
	assert.Empty(t, cmp.Diff(newSecretUpsert.RefreshAtTime, found.RefreshAtTime, protocmp.Transform()))
	require.NoError(t, found.decrypt(ctx, databaseWrapper))
	assert.Empty(t, cmp.Diff(newStructUpsert, found.Secret, protocmp.Transform()))

	// Update
	newStructUpdate := mustMarshal(map[string]interface{}{
		"one": "two",
	})
	newSecretUpdate := newSecretUpsert.clone()
	newSecretUpdate.RefreshAtTime = timestamp.New(time.Now().Add(time.Second * 60))
	newSecretUpdate.Secret = newStructUpdate
	require.NoError(t, newSecretUpdate.encrypt(ctx, databaseWrapper))
	rowsUpdated, err := w.Update(ctx, newSecretUpdate, []string{"CtSecret"}, []string{})
	require.NoError(t, err)
	require.Equal(t, 1, rowsUpdated)
	found = &HostCatalogSecret{
		HostCatalogSecret: &store.HostCatalogSecret{
			CatalogId: cat.GetPublicId(),
		},
	}
	require.NoError(t, w.LookupById(ctx, found))
	assert.Empty(t, cmp.Diff(newSecretUpdate.HostCatalogSecret, found.HostCatalogSecret, protocmp.Transform()))
	require.NoError(t, found.decrypt(ctx, databaseWrapper))
	assert.Empty(t, cmp.Diff(newStructUpdate, found.Secret, protocmp.Transform()))

	// Delete
	rowsDeleted, err := w.Delete(ctx, found)
	require.NoError(t, err)
	require.Equal(t, 1, rowsDeleted)
	err = w.LookupById(ctx, &HostCatalogSecret{
		HostCatalogSecret: &store.HostCatalogSecret{
			CatalogId: cat.GetPublicId(),
		},
	})
	require.Error(t, err)
	require.True(t, errors.IsNotFoundError(err))
}

func TestHostCatalogSecret_TtlError(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	plg := host.TestPlugin(t, conn, "test")
	cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())

	ctx := context.Background()
	databaseWrapper, err := kkms.GetWrapper(ctx, prj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	secret, err := newHostCatalogSecret(ctx, cat.GetPublicId(), -1, mustStruct(map[string]interface{}{
		"foo": "bar",
	}))
	require.NoError(t, err)

	w := db.New(conn)
	require.Error(t, w.Create(ctx, secret))
}
