// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewrap_sessionCredentialRewrapFn(t *testing.T) {
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
			`select distinct cred\.session_id, cred\.key_id, cred\.credential, cred\.credential_sha256 from session inner join session_credential cred on cred\.session_id = session\.public_id where session\.project_id = \$1 and cred\.key_id = \$2`,
		).WillReturnError(errors.New("Query error"))
		err := sessionCredentialRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		rootWrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, rootWrapper)
		rw := db.New(conn)

		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
		at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
		uId := at.GetIamUserId()
		hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
		h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
		static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
		tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
		sess := TestSession(t, conn, rootWrapper, ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ProjectId:   prj.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})

		cred := &credential{
			SessionId:  sess.PublicId,
			Credential: []byte("secret"),
		}

		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
		require.NoError(t, err)

		require.NoError(t, cred.encrypt(ctx, kmsWrapper))
		require.NoError(t, rw.Create(ctx, cred))

		// now things are stored in the db, we can rotate and rewrap
		require.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		require.NoError(t, sessionCredentialRewrapFn(ctx, cred.KeyId, prj.PublicId, rw, rw, kmsCache))

		// now we pull the credential back from the db, decrypt it with the new key, and ensure things match
		got := &credential{
			SessionId: sess.PublicId,
		}
		// this is the best way we have to query for this. there's only one index on this table and it's on session id and sha256. since we're testing there should be no others.
		rows, err := rw.Query(ctx, `select credential, key_id, credential_sha256 from session_credential where session_id = ?`, []any{got.SessionId})
		require.NoError(t, err)
		rowCount := 0

		for rows.Next() {
			rowCount++
			require.NoError(t, rows.Scan(&got.CtCredential, &got.KeyId, &got.CredentialSha256))
		}
		require.NoError(t, rows.Err())
		assert.Equal(t, 1, rowCount)

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.KeyId))
		require.NoError(t, err)

		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		require.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		require.NoError(t, got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.KeyId)
		assert.NotEqual(t, cred.KeyId, got.KeyId)
		assert.Equal(t, newKeyVersionId, got.KeyId)
		assert.Equal(t, "secret", string(got.Credential))
		assert.NotEmpty(t, got.CredentialSha256)
		assert.NotEqual(t, cred.CredentialSha256, got.CredentialSha256)
		assert.NotEqual(t, cred.CtCredential, got.CtCredential)
	})
}

func TestRewrap_sessionRewrapFn(t *testing.T) {
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
			`SELECT \* FROM "session" WHERE project_id=\$1 and key_id=\$2`,
		).WillReturnError(errors.New("Query error"))
		err := sessionRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		rootWrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, rootWrapper)
		rw := db.New(conn)

		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
		at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
		uId := at.GetIamUserId()
		hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
		h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
		static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
		tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
		session := TestSession(t, conn, rootWrapper, ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ProjectId:   prj.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})
		// you cannot create a session with a pre-populated token, so do it in an update
		session.TofuToken = []byte("token")
		sessionWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeSessions)
		require.NoError(t, err)
		require.NoError(t, session.encrypt(ctx, sessionWrapper))
		_, err = rw.Update(ctx, session, []string{"CtTofuToken", "CertificatePrivateKey", "KeyId"}, nil)
		require.NoError(t, err)

		// now things are stored in the db, we can rotate and rewrap
		require.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		require.NoError(t, sessionRewrapFn(ctx, session.KeyId, prj.PublicId, rw, rw, kmsCache))

		// now we pull the session back from the db, decrypt it with the new key, and ensure things match
		got := &Session{}
		got.PublicId = session.PublicId
		require.NoError(t, rw.LookupById(ctx, got))

		sessionWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeSessions, kms.WithKeyId(got.KeyId))
		require.NoError(t, err)

		newKeyVersionId, err := sessionWrapper2.KeyId(ctx)
		require.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		require.NoError(t, got.decrypt(ctx, sessionWrapper2))
		assert.NotEmpty(t, got.KeyId)
		assert.NotEqual(t, session.KeyId, got.KeyId)
		assert.Equal(t, newKeyVersionId, got.KeyId)
		assert.Equal(t, "token", string(got.TofuToken))
		assert.NotEqual(t, session.CtTofuToken, got.CtTofuToken)
		// there is no hmac, so we're done
	})
	t.Run("unsets-key-id-when-user-id-unset", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		rootWrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, rootWrapper)
		rw := db.New(conn)

		iamRepo := iam.TestRepo(t, conn, rootWrapper)
		org, prj := iam.TestScopes(t, iamRepo)
		at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
		uId := at.GetIamUserId()
		hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
		h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
		static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
		tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
		session := TestSession(t, conn, rootWrapper, ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ProjectId:   prj.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})
		// you cannot create a session with a pre-populated token, so do it in an update
		session.TofuToken = []byte("token")
		sessionWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeSessions)
		require.NoError(t, err)
		require.NoError(t, session.encrypt(ctx, sessionWrapper))
		_, err = rw.Update(ctx, session, []string{"CtTofuToken", "CertificatePrivateKey", "KeyId"}, nil)
		require.NoError(t, err)

		// Deleting the user unsets the user ID in the session
		_, err = iamRepo.DeleteUser(ctx, uId)
		require.NoError(t, err)

		// now things are stored in the db, we can rotate and rewrap
		require.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		require.NoError(t, sessionRewrapFn(ctx, session.KeyId, prj.PublicId, rw, rw, kmsCache))

		// now we pull the session back from the db and check that the key ID is unset
		got := &Session{}
		got.PublicId = session.PublicId
		require.NoError(t, rw.LookupById(ctx, got))
		assert.Empty(t, got.KeyId)
	})
}

func TestRewrap_sessionProxyCertificateRewrapFn(t *testing.T) {
	ctx := t.Context()
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
			`SELECT \* FROM "session_proxy_certificate" WHERE key_id=\$1`,
		).WillReturnError(errors.New("Query error"))
		err := sessionProxyCertificateRewrapFn(ctx, "some_id", "some_scope", rw, rw, kmsCache)
		require.Error(t, err)
	})
	t.Run("success", func(t *testing.T) {
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		iam.TestScopes(t, iam.TestRepo(t, conn, wrapper)) // despite not looking like it, this is necessary for some reason
		org, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), proj.PublicId, kms.KeyPurposeSessions)
		require.NoError(t, err)

		at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
		uId := at.GetIamUserId()
		hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
		h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
		static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
		tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
		session := TestSession(t, conn, wrapper, ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ProjectId:   proj.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})

		encryptedKeyValue := []byte("fake-encrypted-key")
		cert, err := NewProxyCertificate(ctx, session.PublicId, encryptedKeyValue, []byte("fake-cert"))
		require.NoError(t, err)
		require.NotNil(t, cert)

		err = cert.Encrypt(ctx, kmsWrapper)
		require.NoError(t, err)
		err = rw.Create(ctx, cert)
		require.NoError(t, err)

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, proj.PublicId))
		assert.NoError(t, sessionProxyCertificateRewrapFn(ctx, cert.KeyId, proj.PublicId, rw, rw, kmsCache))

		// now we pull it from the db, decrypt it with the new key, and ensure things match
		got := allocProxyCertificate()
		got.SessionId = cert.SessionId
		assert.NoError(t, rw.LookupById(ctx, got))

		kmsWrapper2, err := kmsCache.GetWrapper(ctx, proj.PublicId, kms.KeyPurposeSessions, kms.WithKeyId(got.KeyId))
		assert.NoError(t, err)
		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.Decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.KeyId)
		assert.Equal(t, newKeyVersionId, got.KeyId)
		assert.Equal(t, cert.PrivateKey, got.PrivateKey)
		assert.Equal(t, cert.Certificate, got.Certificate)
	})
}
