package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/dbtest"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrations_UserDimension(t *testing.T) {
	const (
		priorMigration   = 13001
		currentMigration = 14001
	)

	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(err)
	t.Cleanup(func() {
		require.NoError(c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(err)

	// migration to the prior migration (before the one we want to test)
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": priorMigration}),
	))
	require.NoError(err)

	assert.NoError(m.ApplyMigrations(ctx))
	state, err := m.CurrentState(ctx)
	require.NoError(err)
	want := &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   priorMigration,
				DatabaseSchemaVersion: priorMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(want, state)

	// okay, now we can seed the database with test data
	dbType, err := db.StringToDbType(dialect)
	require.NoError(err)
	conn, err := db.Open(dbType, u)
	require.NoError(err)

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]

	for _, h := range []*static.Host{h} {
		w := db.New(conn)
		_, err := w.Query(context.Background(), "insert into static_host_set_member(set_id, host_id, catalog_id) values (?, ?, ?)", []interface{}{hs.GetPublicId(), h.GetPublicId(), hc.GetPublicId()})
		assert.NoError(err)
	}

	tar := target.TestTcpTarget(t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	var sessions []*session.Session

	kmsCache := kms.TestKms(t, conn, wrapper)
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(err)

	{
		at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
		uId := at.GetIamUserId()

		sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ScopeId:     prj.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})
		sessions = append(sessions, sess)
	}

	{
		at := testOidcAuthToken(t, conn, kmsCache, databaseWrapper, org.GetPublicId())
		uId := at.GetIamUserId()

		sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ScopeId:     prj.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})
		sessions = append(sessions, sess)
	}

	sessionRepo, err := session.NewRepository(rw, rw, kmsCache)
	require.NoError(err)

	count, err := sessionRepo.TerminateCompletedSessions(ctx)
	assert.NoError(err)
	assert.Zero(count)

	for _, sess := range sessions {
		// call TerminateSession
		_, err = sessionRepo.TerminateSession(ctx, sess.GetPublicId(), 1, session.ClosedByUser)
		assert.NoError(err)
	}

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(err)

	assert.NoError(m.ApplyMigrations(ctx))
	state, err = m.CurrentState(ctx)
	require.NoError(err)
	want = &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   currentMigration,
				DatabaseSchemaVersion: currentMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(want, state)
}

func testOidcAuthToken(t *testing.T, conn *db.DB, kms *kms.Kms, wrapper wrapping.Wrapper, scopeId string) *authtoken.AuthToken {
	t.Helper()

	authMethod := oidc.TestAuthMethod(
		t, conn, wrapper, scopeId, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	acct := oidc.TestAccount(t, conn, authMethod, "test-subject")

	ctx := context.Background()
	rw := db.New(conn)
	iamRepo, err := iam.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	u := iam.TestUser(t, iamRepo, scopeId, iam.WithAccountIds(acct.PublicId))

	repo, err := authtoken.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	at, err := repo.CreateAuthToken(ctx, u, acct.GetPublicId())
	require.NoError(t, err)
	return at
}
