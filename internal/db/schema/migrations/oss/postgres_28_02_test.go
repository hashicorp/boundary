package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

func TestMigrations_SessionStateTrigger(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	const (
		priorMigration   = 27002
		currentMigration = 28002
	)
	dialect := dbtest.Postgres
	ctx := context.Background()

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

	require.NoError(m.ApplyMigrations(ctx))
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

	// Seed the database with test data
	dbType, err := db.StringToDbType(dialect)
	require.NoError(err)

	conn, err := db.Open(dbType, u)
	require.NoError(err)

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)

	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	kmsCache := kms.TestKms(t, conn, wrapper)

	serverId := "worker"
	tofu := session.TestTofu(t)
	session.TestWorker(t, conn, wrapper, session.WithServerId(serverId))
	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:          uId,
		HostId:          h.GetPublicId(),
		TargetId:        tar.GetPublicId(),
		HostSetId:       hs.GetPublicId(),
		AuthTokenId:     at.GetPublicId(),
		ScopeId:         prj.GetPublicId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ConnectionLimit: 1,
	})

	sessionRepo, err := session.NewRepository(rw, rw, kmsCache)
	require.NoError(err)

	// Make and transition a valid session through pending, active, canceling, and terminated
	// Unfortunately, could not recreate an invalid session P-A-T-C using the session repo
	_, _, err = sessionRepo.ActivateSession(ctx, sess.PublicId, sess.Version, serverId, resource.Worker.String(), tofu)
	require.NoError(err)
	connection := session.TestConnection(t, conn, sess.PublicId, "127.0.0.1", 22,
		"127.0.0.2", 23, "127.0.0.1")
	session.TestConnectionState(t, conn, connection.PublicId, session.StatusConnected)
	session.TestConnectionState(t, conn, connection.PublicId, session.StatusClosed)
	_, err = sessionRepo.CancelSession(ctx, sess.PublicId, sess.Version+1)
	require.NoError(err)
	sessionRepo.TerminateCompletedSessions(ctx)

	repoSessions, err := sessionRepo.ListSessions(ctx)
	require.NoError(err)
	var numStates int
	for _, s := range repoSessions {
		numStates = len(s.States)
	}
	require.Equal(4, numStates)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(err)

	require.NoError(m.ApplyMigrations(ctx))
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

	// Check that we haven't removed a state
	repoSessions, err = sessionRepo.ListSessions(ctx)
	require.NoError(err)
	for _, s := range repoSessions {
		numStates = len(s.States)
	}
	require.Equal(4, numStates)
}
