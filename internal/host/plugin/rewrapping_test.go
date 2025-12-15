// Copyright IBM Corp. 2020, 2025
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
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewrap_hostCatalogSecretRewrapFn(t *testing.T) {
	ctx := context.Background()
	t.Run("errors-on-query-error", func(t *testing.T) {
		conn, mock := db.TestSetupWithMock(t)
		wrapper := db.TestWrapper(t)
		mock.ExpectQuery(
			`SELECT \* FROM "kms_schema_version" WHERE 1=1 ORDER BY "kms_schema_version"\."version" LIMIT \$1`,
		).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
		mock.ExpectQuery(
			`SELECT \* FROM "kms_oplog_schema_version" WHERE 1=1 ORDER BY "kms_oplog_schema_version"."version" LIMIT \$1`,
		).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)
		mock.ExpectQuery(
			`SELECT \* FROM "host_plugin_catalog_secret" WHERE key_id=\$1`,
		).WillReturnError(errors.New("Query error"))
		err := hostCatalogSecretRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		plg := plugin.TestPlugin(t, conn, "test")
		cat := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
		secret, err := newHostCatalogSecret(ctx, cat.GetPublicId(), mustStruct(map[string]any{
			"foo": "bar",
		}))
		assert.NoError(t, err)
		assert.NotNil(t, secret)
		assert.Empty(t, secret.CtSecret)
		assert.NotEmpty(t, secret.Secret)

		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
		assert.NoError(t, err)
		secretSecret := secret.GetSecret() // this is cleared by the encrypt function, so save it for assert
		assert.NoError(t, secret.encrypt(ctx, kmsWrapper))
		assert.NoError(t, rw.Create(context.Background(), secret))

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		assert.NoError(t, hostCatalogSecretRewrapFn(ctx, secret.GetKeyId(), prj.PublicId, rw, rw, kmsCache))

		// now we pull the credential back from the db, decrypt it with the new key, and ensure things match
		got := allocHostCatalogSecret()
		got.CatalogId = cat.GetPublicId()
		assert.NoError(t, rw.LookupById(ctx, got))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)

		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, secret.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.Equal(t, secretSecret, got.GetSecret())
		assert.NotEqual(t, secret.GetCtSecret(), got.GetCtSecret())
	})
}
