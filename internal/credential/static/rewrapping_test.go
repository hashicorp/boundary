// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewrap_credStaticUsernamePasswordRewrapFn(t *testing.T) {
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
			`select distinct userpass\.public_id, userpass\.password_encrypted, userpass\.key_id from credential_static_username_password_credential userpass inner join credential_static_store store on store\.public_id = userpass\.store_id where store\.project_id = \$1 and userpass\.key_id = \$2;`,
		).WillReturnError(errors.New("Query error"))
		err := credStaticUsernamePasswordRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)
		cred, err := NewUsernamePasswordCredential(cs.GetPublicId(), "username", "password")
		assert.NoError(t, err)

		cred.PublicId, err = credential.NewUsernamePasswordCredentialId(ctx)
		assert.NoError(t, err)

		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
		assert.NoError(t, err)

		assert.NoError(t, cred.encrypt(ctx, kmsWrapper))
		assert.NoError(t, rw.Create(context.Background(), cred))

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		assert.NoError(t, credStaticUsernamePasswordRewrapFn(ctx, cred.GetKeyId(), prj.PublicId, rw, rw, kmsCache))

		// now we pull the credential back from the db, decrypt it with the new key, and ensure things match
		got := allocUsernamePasswordCredential()
		got.PublicId = cred.PublicId
		assert.NoError(t, rw.LookupById(ctx, got))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)
		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, cred.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.Equal(t, "password", string(got.GetPassword()))
		assert.NotEmpty(t, got.GetPasswordHmac())
		assert.Equal(t, cred.GetPasswordHmac(), got.GetPasswordHmac())
	})
}

func TestRewrap_credStaticSshPrivKeyRewrapFn(t *testing.T) {
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
			`select distinct ssh\.public_id, ssh\.private_key_encrypted, ssh\.private_key_passphrase_encrypted, ssh\.key_id from credential_static_ssh_private_key_credential ssh inner join credential_static_store store on store\.public_id = ssh\.store_id where store\.project_id = \$1 and ssh\.key_id = \$2;`,
		).WillReturnError(errors.New("Query error"))
		err := credStaticSshPrivKeyRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)

		// since there are two possible versions (with or without passphrase) we need to make 2 copies of everything, but rewrap only once
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)
		cs2 := TestCredentialStore(t, conn, wrapper, prj.PublicId)

		cred, err := NewSshPrivateKeyCredential(ctx, cs.GetPublicId(), "username", credential.PrivateKey(TestSshPrivateKeyPem))
		assert.NoError(t, err)

		// we need to assign this one explicitly since the new function (correctly) has some checks on the passphrase actually being correct
		cred2 := &SshPrivateKeyCredential{
			SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
				StoreId:              cs2.GetPublicId(),
				Username:             "username",
				PrivateKey:           credential.PrivateKey(TestSshPrivateKeyPem),
				PrivateKeyPassphrase: []byte("passphrase"),
			},
		}

		cred.PublicId, err = credential.NewSshPrivateKeyCredentialId(ctx)
		assert.NoError(t, err)
		cred2.PublicId, err = credential.NewSshPrivateKeyCredentialId(ctx)
		assert.NoError(t, err)

		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
		assert.NoError(t, err)

		assert.NoError(t, cred.encrypt(ctx, kmsWrapper))
		assert.NoError(t, cred2.encrypt(ctx, kmsWrapper))

		// create them in the db
		assert.NoError(t, rw.Create(context.Background(), cred))
		assert.NoError(t, rw.Create(context.Background(), cred2))

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		assert.NoError(t, credStaticSshPrivKeyRewrapFn(ctx, cred.GetKeyId(), prj.PublicId, rw, rw, kmsCache))

		// now we pull both credential2 back from the db, decrypt them with the new key, and ensure things match
		got := allocSshPrivateKeyCredential()
		got.PublicId = cred.PublicId
		assert.NoError(t, rw.LookupById(ctx, got))

		got2 := allocSshPrivateKeyCredential()
		got2.PublicId = cred2.PublicId
		assert.NoError(t, rw.LookupById(ctx, got2))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)

		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, cred.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.Equal(t, TestSshPrivateKeyPem, string(got.PrivateKey))
		assert.NotEqual(t, cred.GetPrivateKeyEncrypted(), got.GetPrivateKeyEncrypted())
		assert.NotEmpty(t, got.GetPrivateKeyHmac())
		assert.Equal(t, cred.GetPrivateKeyHmac(), got.GetPrivateKeyHmac())
		// we didn't set this, so they should be empty before AND after rewrapping
		assert.Empty(t, got.GetPrivateKeyPassphrase())
		assert.Empty(t, got.GetPrivateKeyPassphraseHmac())
		assert.Empty(t, got.GetPrivateKeyPassphraseEncrypted())

		// perform all the same checks again on #2, but also check passphrase
		assert.NoError(t, got2.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got2.GetKeyId())
		assert.NotEqual(t, cred2.GetKeyId(), got2.GetKeyId())
		assert.Equal(t, newKeyVersionId, got2.GetKeyId())
		assert.Equal(t, TestSshPrivateKeyPem, string(got2.PrivateKey))
		assert.NotEqual(t, cred.GetPrivateKeyEncrypted(), got.GetPrivateKeyEncrypted())
		assert.NotEmpty(t, got2.GetPrivateKeyHmac())
		assert.Equal(t, cred2.GetPrivateKeyHmac(), got2.GetPrivateKeyHmac())
		// this time, we did set this, so they should be available
		assert.NotEmpty(t, got2.GetPrivateKeyPassphraseEncrypted())
		assert.NotEmpty(t, got2.GetPrivateKeyPassphraseHmac())
		assert.Equal(t, []byte("passphrase"), got2.GetPrivateKeyPassphrase())
		assert.Equal(t, cred2.GetPrivateKeyPassphraseHmac(), got2.GetPrivateKeyPassphraseHmac())
	})
}

func TestRewrap_credStaticJsonRewrapFn(t *testing.T) {
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
			`select distinct json\.public_id, json\.object_encrypted, json\.key_id from credential_static_json_credential json inner join credential_static_store store on store\.public_id = json\.store_id where store\.project_id = \$1 and json\.key_id = \$2;`,
		).WillReturnError(errors.New("Query error"))
		err := credStaticJsonRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)
		obj, objBytes := TestJsonObject(t)
		cred, err := NewJsonCredential(ctx, cs.GetPublicId(), obj)
		assert.NoError(t, err)

		cred.PublicId, err = credential.NewJsonCredentialId(ctx)
		assert.NoError(t, err)

		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
		assert.NoError(t, err)

		assert.NoError(t, cred.encrypt(ctx, kmsWrapper))
		assert.NoError(t, rw.Create(context.Background(), cred))

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		assert.NoError(t, credStaticJsonRewrapFn(ctx, cred.GetKeyId(), prj.PublicId, rw, rw, kmsCache))

		// now we pull the credential back from the db, decrypt it with the new key, and ensure things match
		got := allocJsonCredential()
		got.PublicId = cred.PublicId
		assert.NoError(t, rw.LookupById(ctx, got))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)
		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, cred.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.Equal(t, objBytes, got.GetObject())
		assert.NotEmpty(t, got.GetObjectHmac())
		assert.Equal(t, cred.GetObjectHmac(), got.GetObjectHmac())
	})
}

func TestRewrap_credStaticUsernamePasswordDomainRewrapFn(t *testing.T) {
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
			`select distinct upd\.public_id, upd\.password_encrypted, upd\.key_id from credential_static_username_password_credential upd inner join credential_static_store store on store\.public_id = upd\.store_id where store\.project_id = \$1 and upd\.key_id = \$2;`,
		).WillReturnError(errors.New("Query error"))
		err := credStaticUsernamePasswordDomainRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)

		cred, err := NewUsernamePasswordDomainCredential(cs.GetPublicId(), "username", "password", "domain")
		assert.NoError(t, err)

		cred.PublicId, err = credential.NewUsernamePasswordCredentialId(ctx)
		assert.NoError(t, err)

		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
		assert.NoError(t, err)

		assert.NoError(t, cred.encrypt(ctx, kmsWrapper))
		assert.NoError(t, rw.Create(context.Background(), cred))

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		assert.NoError(t, credStaticUsernamePasswordDomainRewrapFn(ctx, cred.GetKeyId(), prj.PublicId, rw, rw, kmsCache))

		// now we pull the credential back from the db, decrypt it with the new key, and ensure things match
		got := allocUsernamePasswordDomainCredential()
		got.PublicId = cred.PublicId
		assert.NoError(t, rw.LookupById(ctx, got))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)
		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, cred.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.Equal(t, "password", string(got.GetPassword()))
		assert.NotEmpty(t, got.GetPasswordHmac())
		assert.Equal(t, cred.GetPasswordHmac(), got.GetPasswordHmac())
	})
}

func TestRewrap_credStaticPasswordRewrapFn(t *testing.T) {
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
			`select distinct pass\.public_id, pass\.password_encrypted, pass\.key_id from credential_static_password_credential pass inner join credential_static_store store on store\.public_id = pass\.store_id where store\.project_id = \$1 and pass\.key_id = \$2;`,
		).WillReturnError(errors.New("Query error"))
		err := credStaticPasswordRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)
		cred, err := NewPasswordCredential(cs.GetPublicId(), "password")
		assert.NoError(t, err)

		cred.PublicId, err = credential.NewPasswordCredentialId(ctx)
		assert.NoError(t, err)

		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
		assert.NoError(t, err)

		assert.NoError(t, cred.encrypt(ctx, kmsWrapper))
		assert.NoError(t, rw.Create(context.Background(), cred))

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		assert.NoError(t, credStaticPasswordRewrapFn(ctx, cred.GetKeyId(), prj.PublicId, rw, rw, kmsCache))

		// now we pull the credential back from the db, decrypt it with the new key, and ensure things match
		got := allocPasswordCredential()
		got.PublicId = cred.PublicId
		assert.NoError(t, rw.LookupById(ctx, got))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)
		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, cred.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersionId, got.GetKeyId())
		assert.Equal(t, "password", string(got.GetPassword()))
		assert.NotEmpty(t, got.GetPasswordHmac())
		assert.Equal(t, cred.GetPasswordHmac(), got.GetPasswordHmac())
	})
}
