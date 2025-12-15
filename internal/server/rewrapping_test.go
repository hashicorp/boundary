// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewrap_workerAuthCertRewrapFn(t *testing.T) {
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
			`SELECT \* FROM "worker_auth_ca_certificate" WHERE key_id=\$1`,
		).WillReturnError(errors.New("Query error"))
		err := workerAuthCertRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		iam.TestScopes(t, iam.TestRepo(t, conn, wrapper)) // despite not looking like it, this is necessary for some reason

		// create a repo and rotate to generate the first auth cert
		workerAuthRepo, err := NewRepositoryStorage(ctx, rw, rw, kmsCache)
		assert.NoError(t, err)
		roots, err := rotation.RotateRootCertificates(ctx, workerAuthRepo)
		assert.NoError(t, err)

		// pull this directly from the db rather than convert so we don't lose key info
		currentRoot := allocRootCertificate()
		assert.NoError(t, rw.SearchWhere(ctx, &currentRoot, "state = ?", []any{"current"}, db.WithLimit(-1)))

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, scope.Global.String()))
		assert.NoError(t, workerAuthCertRewrapFn(ctx, currentRoot.KeyId, scope.Global.String(), rw, rw, kmsCache))

		// now we pull the certs back from the db, decrypt it with the new key, and ensure things match
		got := allocRootCertificate()
		assert.NoError(t, rw.SearchWhere(ctx, &got, "state = ?", []any{"current"}, db.WithLimit(-1)))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)
		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, currentRoot.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.NotEqual(t, currentRoot.GetCtPrivateKey(), got.GetCtPrivateKey())
		assert.Equal(t, roots.Current.PrivateKeyPkcs8, got.GetPrivateKey())
	})
}

func TestRewrap_workerAuthRewrapFn(t *testing.T) {
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
			`select distinct auth\.worker_key_identifier, auth\.controller_encryption_priv_key, auth\.key_id from server_worker worker inner join worker_auth_authorized auth on auth\.worker_id = worker\.public_id where worker\.scope_id = \$1 and auth\.key_id = \$2`,
		).WillReturnError(errors.New("Query error"))
		err := workerAuthRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		iam.TestScopes(t, iam.TestRepo(t, conn, wrapper)) // despite not looking like it, this is necessary for some reason

		worker := TestPkiWorker(t, conn, wrapper)
		kmsWrapper, err := kmsCache.GetWrapper(ctx, worker.GetScopeId(), kms.KeyPurposeDatabase)
		assert.NoError(t, err)
		workerAuth := TestWorkerAuth(t, conn, worker, kmsWrapper)

		// TestWorkerAuth DOES encrypt the entry, so just store in the db
		rows, err := rw.Update(ctx, workerAuth, []string{"CtControllerEncryptionPrivKey"}, nil)
		assert.Equal(t, 1, rows)
		assert.NoError(t, err)

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, scope.Global.String()))
		assert.NoError(t, workerAuthRewrapFn(ctx, workerAuth.GetKeyId(), scope.Global.String(), rw, rw, kmsCache))

		// now we pull the auth back from the db, decrypt it with the new key, and ensure things match
		got := allocWorkerAuth()
		got.WorkerKeyIdentifier = workerAuth.WorkerKeyIdentifier
		assert.NoError(t, rw.LookupById(ctx, got))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), worker.GetScopeId(), kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)
		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, workerAuth.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.NotEqual(t, workerAuth.GetCtControllerEncryptionPrivKey(), got.GetCtControllerEncryptionPrivKey())
		assert.Equal(t, workerAuth.ControllerEncryptionPrivKey, got.GetControllerEncryptionPrivKey())
	})
}

func TestRewrap_workerAuthServerLedActivationTokenRewrapFn(t *testing.T) {
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
			`select distinct auth_token\.worker_id, auth_token\.creation_time_encrypted, auth_token\.key_id from server_worker worker inner join worker_auth_server_led_activation_token auth_token on auth_token\.worker_id = worker\.public_id where worker\.scope_id = \$1 and auth_token\.key_id = \$2`,
		).WillReturnError(errors.New("Query error"))
		err := workerAuthServerLedActivationTokenRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		iam.TestScopes(t, iam.TestRepo(t, conn, wrapper)) // despite not looking like it, this is necessary for some reason

		worker := TestPkiWorker(t, conn, wrapper)
		kmsWrapper, err := kmsCache.GetWrapper(ctx, worker.GetScopeId(), kms.KeyPurposeDatabase)
		assert.NoError(t, err)
		token := &WorkerAuthServerLedActivationToken{
			WorkerAuthServerLedActivationToken: &store.WorkerAuthServerLedActivationToken{
				WorkerId:     worker.GetPublicId(),
				TokenId:      "not a real token id lmao",
				CreationTime: []byte("marshaled timestamppb.Timestamp indeed"),
			},
		}

		// encrypt the entry and store in db
		assert.NoError(t, token.encrypt(ctx, kmsWrapper))
		assert.NoError(t, rw.Create(ctx, token))

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, scope.Global.String()))
		assert.NoError(t, workerAuthServerLedActivationTokenRewrapFn(ctx, token.GetKeyId(), worker.GetScopeId(), rw, rw, kmsCache))

		// now we pull the auth back from the db, decrypt it with the new key, and ensure things match
		got := allocWorkerAuthServerLedActivationToken()
		got.WorkerId = worker.GetPublicId()
		assert.NoError(t, rw.LookupById(ctx, got))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), worker.GetScopeId(), kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)
		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, token.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.NotEqual(t, token.GetCreationTimeEncrypted(), got.GetCreationTimeEncrypted())
		assert.Equal(t, token.GetCreationTime(), got.GetCreationTime())
	})
}
