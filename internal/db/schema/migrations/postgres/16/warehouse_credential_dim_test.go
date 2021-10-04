package migration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/dbtest"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrations_CredentialDimension(t *testing.T) {
	const (
		priorMigration   = 15002
		currentMigration = 16005
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
	d, err := sql.Open(dialect, u)
	require.NoError(err)

	// migration to the prior migration (before the one we want to test)
	oState := schema.TestCloneMigrationStates(t)
	nState := schema.TestCreatePartialMigrationState(oState["postgres"], priorMigration)
	oState["postgres"] = nState

	m, err := schema.NewManager(ctx, dialect, d, schema.WithMigrationStates(oState))
	require.NoError(err)

	assert.NoError(m.RollForward(ctx))
	state, err := m.CurrentState(ctx)
	require.NoError(err)
	assert.Equal(priorMigration, state.DatabaseSchemaVersion)
	assert.False(state.Dirty)

	dbType, err := db.StringToDbType(dialect)
	require.NoError(err)

	// okay, now we can seed the database with test data
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
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})

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
		creds := testSessionCredentialParams(t, conn, kmsCache, wrapper, tar)

		sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
			UserId:             uId,
			HostId:             h.GetPublicId(),
			TargetId:           tar.GetPublicId(),
			HostSetId:          hs.GetPublicId(),
			AuthTokenId:        at.GetPublicId(),
			ScopeId:            prj.GetPublicId(),
			Endpoint:           "tcp://127.0.0.1:22",
			DynamicCredentials: creds,
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
	oState = schema.TestCloneMigrationStates(t)
	nState = schema.TestCreatePartialMigrationState(oState["postgres"], currentMigration)
	oState["postgres"] = nState

	m, err = schema.NewManager(ctx, dialect, d, schema.WithMigrationStates(oState))
	require.NoError(err)

	assert.NoError(m.RollForward(ctx))
	state, err = m.CurrentState(ctx)
	require.NoError(err)
	assert.Equal(currentMigration, state.DatabaseSchemaVersion)
	assert.False(state.Dirty)
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

func testSessionCredentialParams(t *testing.T, conn *db.DB, kms *kms.Kms, wrapper wrapping.Wrapper, tar *target.TcpTarget) []*session.DynamicCredential {
	t.Helper()
	rw := db.New(conn)

	ctx := context.Background()
	stores := vault.TestCredentialStores(t, conn, wrapper, tar.ScopeId, 1)
	libs := vault.TestCredentialLibraries(t, conn, wrapper, stores[0].GetPublicId(), 2)

	targetRepo, err := target.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	_, _, _, err = targetRepo.AddTargetCredentialSources(ctx, tar.GetPublicId(), tar.GetVersion(), []string{libs[0].PublicId, libs[1].PublicId})
	require.NoError(t, err)
	creds := []*session.DynamicCredential{
		session.NewDynamicCredential(libs[0].GetPublicId(), credential.ApplicationPurpose),
		session.NewDynamicCredential(libs[0].GetPublicId(), credential.IngressPurpose),
		session.NewDynamicCredential(libs[1].GetPublicId(), credential.EgressPurpose),
	}
	return creds
}
