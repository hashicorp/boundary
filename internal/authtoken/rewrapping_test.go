// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtoken

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewrap_authTokenRewrapFn(t *testing.T) {
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
			`SELECT \* FROM "auth_token" WHERE key_id=\$1`,
		).WillReturnError(errors.New("Query error"))
		err := authTokenRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

		// TestAuthToken will create and store the token for us
		at := TestAuthToken(t, conn, kmsCache, org.GetPublicId())

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, org.Scope.GetPublicId()))
		assert.NoError(t, authTokenRewrapFn(ctx, at.GetKeyId(), org.Scope.GetPublicId(), rw, rw, kmsCache))

		// now we pull the authToken back from the db, decrypt it with the new key, and ensure things match
		got := allocAuthToken()
		got.PublicId = at.GetPublicId()
		assert.NoError(t, rw.LookupById(ctx, got))

		// fetch the new key version
		kmsWrapper, err := kmsCache.GetWrapper(ctx, org.Scope.GetPublicId(), kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)
		newKeyVersionId, err := kmsWrapper.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, at.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.Equal(t, at.GetToken(), got.GetToken())
		assert.NotEqual(t, at.GetCtToken(), got.GetCtToken())
	})
}
