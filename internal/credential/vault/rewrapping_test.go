// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

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

func TestRewrap_credVaultClientCertificateRewrapFn(t *testing.T) {
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
			`SELECT \* FROM "credential_vault_client_certificate" WHERE key_id=\$1`,
		).WillReturnError(errors.New("Query error"))
		err := credVaultClientCertificateRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStore(t, conn, wrapper, prj.PublicId, "https://vault.consul.service", "token", "accessor")
		cert, err := NewClientCertificate(ctx, []byte(certPem), []byte(keyPem))
		assert.NoError(t, err)

		cert.StoreId = cs.PublicId

		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
		assert.NoError(t, err)
		assert.NoError(t, cert.encrypt(ctx, kmsWrapper))
		assert.NoError(t, rw.Create(context.Background(), cert))

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		assert.NoError(t, credVaultClientCertificateRewrapFn(ctx, cert.GetKeyId(), prj.PublicId, rw, rw, kmsCache))

		// now we pull the credential back from the db, decrypt it with the new key, and ensure things match
		got := allocClientCertificate()
		got.StoreId = cs.PublicId
		assert.NoError(t, rw.LookupById(ctx, got))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)

		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))

		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, cert.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.Equal(t, keyPem, string(got.GetCertificateKey()))
		assert.NotEmpty(t, got.GetCertificateKeyHmac())
		assert.Equal(t, cert.GetCertificateKeyHmac(), got.GetCertificateKeyHmac())
	})
}

func TestRewrap_credVaultTokenRewrapFn(t *testing.T) {
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
			`SELECT \* FROM "credential_vault_token" WHERE key_id=\$1`,
		).WillReturnError(errors.New("Query error"))
		err := credVaultTokenRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStore(t, conn, wrapper, prj.PublicId, "https://vault.consul.service", "token", "accessor")
		token := cs.outputToken

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		assert.NoError(t, credVaultTokenRewrapFn(ctx, token.GetKeyId(), prj.PublicId, rw, rw, kmsCache))

		// now we pull the token back from the db, decrypt it with the new key, and ensure things match
		got := allocToken()
		assert.NoError(t, rw.LookupWhere(ctx, &got, "store_id = ?", []any{cs.PublicId}))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)
		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, token.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.Equal(t, "token", string(got.GetToken()))
		assert.NotEmpty(t, got.GetTokenHmac())
		// vault token hmacs are calculated differently and should remain the same
		assert.Equal(t, token.GetTokenHmac(), got.GetTokenHmac())
	})
}
