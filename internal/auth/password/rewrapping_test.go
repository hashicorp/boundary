// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewrap_argon2ConfigRewrapFn(t *testing.T) {
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
			`SELECT \* FROM "auth_password_argon2_cred" WHERE key_id=\$1`,
		).WillReturnError(errors.New("Query error"))
		err := argon2ConfigRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")

		rw := db.New(conn)
		wrapper := db.TestWrapper(t)

		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		auts := TestAuthMethods(t, conn, org.GetPublicId(), 1)
		aut := auts[0]
		acct := TestAccount(t, conn, aut.PublicId, "name")
		authMethodId := acct.AuthMethodId
		conf := testArgon2Confs(t, conn, authMethodId, 1)[0]

		kmsCache := kms.TestKms(t, conn, wrapper)
		wrapper, _ = kmsCache.GetWrapper(context.Background(), org.GetPublicId(), 1)

		// actually store it
		cred, err := newArgon2Credential(ctx, acct.PublicId, "this is a password", conf, rand.Reader)
		require.NoError(t, err)

		require.NoError(t, cred.encrypt(ctx, wrapper))
		assert.NoError(t, rw.Create(ctx, cred))

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, org.Scope.GetPublicId()))
		assert.NoError(t, argon2ConfigRewrapFn(ctx, cred.KeyId, org.Scope.GetPublicId(), rw, rw, kmsCache))

		// now we pull the config back from the db, decrypt it with the new key, and ensure things match
		got := &Argon2Credential{
			Argon2Credential: &store.Argon2Credential{
				PrivateId: cred.PrivateId,
			},
		}
		assert.NoError(t, rw.LookupById(ctx, got))

		// fetch the new key version
		kmsWrapper, err := kmsCache.GetWrapper(ctx, org.Scope.GetPublicId(), kms.KeyPurposeDatabase, kms.WithKeyId(got.GetKeyId()))
		assert.NoError(t, err)
		newKeyVersion, err := kmsWrapper.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper))
		assert.NotEmpty(t, got.GetKeyId())
		assert.NotEqual(t, cred.GetKeyId(), got.GetKeyId())
		assert.Equal(t, newKeyVersion, got.GetKeyId())
		assert.Equal(t, cred.GetSalt(), got.GetSalt())
		assert.NotEqual(t, cred.GetCtSalt(), got.GetCtSalt())
	})
}
