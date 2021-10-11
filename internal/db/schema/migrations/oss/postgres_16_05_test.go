package oss_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/testing/dbtest"
	wrapping "github.com/hashicorp/go-kms-wrapping"
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

	tar := tcp.TestTarget(t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
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
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(err)

	assert.NoError(m.ApplyMigrations(ctx))
	state, err = m.CurrentState(ctx)
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

func testSessionCredentialParams(t *testing.T, conn *db.DB, kms *kms.Kms, wrapper wrapping.Wrapper, tar target.Target) []*session.DynamicCredential {
	t.Helper()
	rw := db.New(conn)

	ctx := context.Background()
	stores := vault.TestCredentialStores(t, conn, wrapper, tar.GetScopeId(), 1)
	libs := createVaultLibraries(t, conn, stores[0].GetPublicId())

	targetRepo, err := target.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	_, _, _, err = targetRepo.AddTargetCredentialSources(ctx, tar.GetPublicId(), tar.GetVersion(), []string{libs[0], libs[1]})
	require.NoError(t, err)
	creds := []*session.DynamicCredential{
		session.NewDynamicCredential(libs[0], credential.ApplicationPurpose),
		session.NewDynamicCredential(libs[0], credential.IngressPurpose),
		session.NewDynamicCredential(libs[1], credential.EgressPurpose),
	}
	return creds
}

func createVaultLibraries(t *testing.T, conn *db.DB, storeId string) []string {
	// This helper replaces a call made in an earlier version to
	// vault.TestCredentialLibraries. A new column was added to
	// credential_vault_library in a migration that was added after this
	// test was created. That new column causes the call to
	// vault.TestCredentialLibraries to fail because the column doesn't
	// exist in the version of the migrations to test runs against.

	t.Helper()
	require := require.New(t)
	const query = `
    insert into credential_vault_library
      (store_id, public_id, vault_path, http_method)
    values
      (@store_id, @library_id1, '/path1', 'GET'),
      (@store_id, @library_id2, '/path2', 'GET');
`
	libraryIds := []string{"vl______wvl1", "vl______wvl2"}

	queryValues := []interface{}{
		sql.Named("store_id", storeId),
		sql.Named("library_id1", libraryIds[0]),
		sql.Named("library_id2", libraryIds[1]),
	}

	w := db.New(conn)
	n, err := w.Exec(context.Background(), query, queryValues)
	require.NoError(err)
	require.Equal(n, 2)
	return libraryIds
}
