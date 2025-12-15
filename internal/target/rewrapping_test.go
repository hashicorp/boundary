// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/boundary/globals"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/targettest"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewrap_CertRewrapFn(t *testing.T) {
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
			`SELECT \* FROM "target_proxy_certificate" WHERE key_id=\$1`,
		).WillReturnError(errors.New("Query error"))
		err := target.ProxyCertRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		iam.TestScopes(t, iam.TestRepo(t, conn, wrapper)) // despite not looking like it, this is necessary for some reason
		_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), proj.PublicId, kms.KeyPurposeDatabase)
		require.NoError(t, err)

		tar := targettest.TestNewTestTarget(ctx, t, conn, proj.PublicId, "test-target")

		certKey, err := target.NewTargetProxyCertificate(ctx)
		require.NoError(t, err)
		certKey.TargetId = tar.GetPublicId()
		id, err := db.NewPublicId(ctx, globals.ProxyServerCertificatePrefix)
		require.NoError(t, err)
		certKey.PublicId = id
		err = certKey.Encrypt(ctx, kmsWrapper)
		require.NoError(t, err)
		err = rw.Create(ctx, certKey)
		require.NoError(t, err)

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, proj.PublicId))
		assert.NoError(t, target.ProxyCertRewrapFn(ctx, certKey.KeyId, proj.PublicId, rw, rw, kmsCache))

		// now we pull it from the db, decrypt it with the new key, and ensure things match
		got := target.AllocTargetProxyCertificate()
		got.PublicId = certKey.GetPublicId()
		assert.NoError(t, rw.LookupById(ctx, got))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), proj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)
		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.Decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, certKey.KeyId, got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.NotEqual(t, certKey.UpdateTime, got.UpdateTime)

		certPrivKeyParsed, err := x509.ParseECPrivateKey(certKey.PrivateKey)
		require.NoError(t, err)
		retrievedCertKeyParsed, err := x509.ParseECPrivateKey(got.PrivateKey)
		require.NoError(t, err)
		keysAreEqual := certPrivKeyParsed.Equal(retrievedCertKeyParsed)
		assert.True(t, keysAreEqual, "expected the ECDSA keys to be equal")
	})
}

func TestRewrap_AliasCertRewrapFn(t *testing.T) {
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
			`SELECT \* FROM "target_alias_proxy_certificate" WHERE key_id=\$1`,
		).WillReturnError(errors.New("Query error"))
		err := target.ProxyCertRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		iam.TestScopes(t, iam.TestRepo(t, conn, wrapper)) // despite not looking like it, this is necessary for some reason
		_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), proj.PublicId, kms.KeyPurposeDatabase)
		require.NoError(t, err)

		tar := targettest.TestNewTestTarget(ctx, t, conn, proj.PublicId, "test-target")
		aliasValue := "test-alias"
		alias := talias.TestAlias(t, rw, aliasValue, talias.WithDestinationId(tar.GetPublicId()))
		require.NoError(t, err)
		require.NotNil(t, alias)

		certKey, err := target.NewTargetAliasProxyCertificate(ctx, tar.GetPublicId(), alias)
		require.NoError(t, err)
		id, err := db.NewPublicId(ctx, globals.ProxyServerCertificatePrefix)
		require.NoError(t, err)
		certKey.PublicId = id
		err = certKey.Encrypt(ctx, kmsWrapper)
		require.NoError(t, err)
		err = rw.Create(ctx, certKey)
		require.NoError(t, err)

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, proj.PublicId))
		assert.NoError(t, target.ProxyAliasCertRewrapFn(ctx, certKey.KeyId, proj.PublicId, rw, rw, kmsCache))

		// now we pull it from the db, decrypt it with the new key, and ensure things match
		got := target.AllocTargetAliasProxyCertificate()
		got.PublicId = certKey.GetPublicId()
		assert.NoError(t, rw.LookupById(ctx, got))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), proj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)
		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.Decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, certKey.KeyId, got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.NotEqual(t, certKey.UpdateTime, got.UpdateTime)

		certPrivKeyParsed, err := x509.ParseECPrivateKey(certKey.PrivateKey)
		require.NoError(t, err)
		retrievedCertKeyParsed, err := x509.ParseECPrivateKey(got.PrivateKey)
		require.NoError(t, err)
		keysAreEqual := certPrivKeyParsed.Equal(retrievedCertKeyParsed)
		assert.True(t, keysAreEqual, "expected the ECDSA keys to be equal")
	})
}
