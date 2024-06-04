// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/patchstruct"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/storage/plugin/store"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestRewrap_storageBucketCredentialManagedSecretRewrapFn(t *testing.T) {
	ctx := context.Background()
	t.Run("errors-on-query-error", func(t *testing.T) {
		conn, mock := db.TestSetupWithMock(t)
		wrapper := db.TestWrapper(t)
		mock.ExpectQuery(
			`SELECT \* FROM "kms_schema_version" WHERE 1=1 ORDER BY "kms_schema_version"\."version" LIMIT \$1`,
		).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
		mock.ExpectQuery(
			`SELECT \* FROM "kms_oplog_schema_version" WHERE 1=1 ORDER BY "kms_oplog_schema_version"\."version" LIMIT \$1`,
		).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)
		mock.ExpectQuery(
			`SELECT \* FROM "storage_plugin_storage_bucket_secret" WHERE key_id=\$1`,
		).WillReturnError(errors.New("Query error"))
		err := storageBucketCredentialManagedSecretRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		require, assert := require.New(t), assert.New(t)
		conn, _ := db.TestSetup(t, "postgres")

		rw := db.New(conn)
		wrapper := db.TestWrapper(t)

		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		plg := plugin.TestPlugin(t, conn, "test", plugin.WithStorageFlag(true))

		kmsCache := kms.TestKms(t, conn, wrapper)
		sb := &StorageBucket{
			StorageBucket: &store.StorageBucket{
				ScopeId:      org.PublicId,
				PluginId:     plg.PublicId,
				BucketName:   "test-bucket-name",
				Attributes:   []byte{},
				SecretsHmac:  []byte("test"),
				WorkerFilter: "test worker filter",
			},
			Secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"AWS_ACCESS_KEY_ID":     structpb.NewStringValue("access_key_id"),
					"AWS_SECRET_ACCESS_KEY": structpb.NewStringValue("secret_access_key"),
				},
			},
		}

		// first store bucket
		var err error
		sb.PublicId, err = newStorageBucketId(ctx)
		require.NoError(err)
		sb.Attributes, err = patchstruct.PatchBytes([]byte{}, sb.Attributes)
		require.NoError(err)
		require.NoError(rw.Create(ctx, sb))

		// now store secret
		cred, err := newStorageBucketCredentialManagedSecret(ctx, sb.PublicId, sb.Secrets)
		require.NoError(err)
		kmsWrapper1, err := kmsCache.GetWrapper(context.Background(), org.GetPublicId(), 1)
		require.NoError(err)
		require.NoError(cred.encrypt(ctx, kmsWrapper1))
		require.NoError(rw.Create(ctx, cred))
		assert.NoError(cred.decrypt(ctx, kmsWrapper1))

		// now things are stored in the db, we can rotate and rewrap
		require.NoError(kmsCache.RotateKeys(ctx, org.Scope.GetPublicId()))
		require.NoError(storageBucketCredentialManagedSecretRewrapFn(ctx, cred.KeyId, org.Scope.GetPublicId(), rw, rw, kmsCache))

		// now we pull the config back from the db, decrypt it with the new key, and ensure things match
		got := &StorageBucketCredentialManagedSecret{
			StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{
				StorageBucketId: sb.PublicId,
			},
		}
		assert.NoError(rw.LookupById(ctx, got))

		// fetch the new key version
		kmsWrapper2, err := kmsCache.GetWrapper(ctx, org.Scope.GetPublicId(), kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(err)
		newKeyVersion, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(got.GetKeyId())
		assert.NotEqual(cred.GetKeyId(), got.GetKeyId())
		assert.Equal(newKeyVersion, got.GetKeyId())
		assert.Equal(cred.Secrets, got.GetSecrets())
	})
}
