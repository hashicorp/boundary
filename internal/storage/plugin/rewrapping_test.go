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
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/stretchr/testify/require"
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
		err := storageBucketCredentialRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
}
