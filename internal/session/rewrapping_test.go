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
			`SELECT \* FROM "kms_schema_version" WHERE 1=1 ORDER BY "kms_schema_version"\."version" LIMIT 1`,
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
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)

		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
		uId := at.GetIamUserId()
		hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
		h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
		static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
		tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
		sess := TestSession(t, conn, wrapper, ComposedOf{
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
		assert.NoError(t, err)

		assert.NoError(t, cred.encrypt(ctx, kmsWrapper))
		assert.NoError(t, rw.Create(ctx, cred))

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		assert.NoError(t, sessionCredentialRewrapFn(ctx, cred.KeyId, prj.PublicId, rw, rw, kmsCache))

		// now we pull the credential back from the db, decrypt it with the new key, and ensure things match
		got := &credential{
			SessionId: sess.PublicId,
		}
		// this is the best way we have to query for this. there's only one index on this table and it's on session id and sha256. since we're testing there should be no others.
		rows, err := rw.Query(ctx, `select credential, key_id, credential_sha256 from session_credential where session_id = ?`, []interface{}{got.SessionId})
		assert.NoError(t, err)
		rowCount := 0

		for rows.Next() {
			rowCount++
			assert.NoError(t, rows.Scan(&got.CtCredential, &got.KeyId, &got.CredentialSha256))
		}
		assert.Equal(t, 1, rowCount)

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.KeyId))
		assert.NoError(t, err)

		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
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
			`SELECT \* FROM "kms_schema_version" WHERE 1=1 ORDER BY "kms_schema_version"\."version" LIMIT 1`,
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
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)

		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
		uId := at.GetIamUserId()
		hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
		h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
		static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
		tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
		assert.NoError(t, err)
		session := TestSession(t, conn, kmsWrapper, ComposedOf{
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
		assert.NoError(t, session.encrypt(ctx, kmsWrapper))
		_, err = rw.Update(ctx, session, []string{"CtTofuToken", "KeyId"}, nil)
		assert.NoError(t, err)

		// now things are stored in the db, we can rotate and rewrap
		assert.NoError(t, kmsCache.RotateKeys(ctx, prj.PublicId))
		assert.NoError(t, sessionRewrapFn(ctx, session.KeyId, prj.PublicId, rw, rw, kmsCache))

		// now we pull the session back from the db, decrypt it with the new key, and ensure things match
		got := &Session{}
		got.PublicId = session.PublicId
		assert.NoError(t, rw.LookupById(ctx, got))

		kmsWrapper2, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase, kms.WithKeyId(got.KeyId))
		assert.NoError(t, err)

		newKeyVersionId, err := kmsWrapper2.KeyId(ctx)
		assert.NoError(t, err)

		// decrypt with the new key version and check to make sure things match
		assert.NoError(t, got.decrypt(ctx, kmsWrapper2))
		assert.NotEmpty(t, got.KeyId)
		assert.NotEqual(t, session.KeyId, got.KeyId)
		assert.Equal(t, newKeyVersionId, got.KeyId)
		assert.Equal(t, "token", string(got.TofuToken))
		assert.NotEqual(t, session.CtTofuToken, got.CtTofuToken)
		// there is no hmac, so we're done
	})
}
