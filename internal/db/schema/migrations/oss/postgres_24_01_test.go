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
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

func TestMigrations_SessionState(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	const (
		priorMigration   = 21002
		currentMigration = 24001
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

	{
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
			ConnectionLimit: -1,
		})

		session.TestConnection(t, conn, sess.PublicId, "127.0.0.1", 22,
			"127.0.0.2", 23, "127.0.0.1")
	}

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

	sessionRepo, err := session.NewRepository(rw, rw, kmsCache)
	connectionRepo, err := session.NewConnectionRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)

	// Ensure session is cancelled
	repoSessions, err := sessionRepo.ListSessions(ctx)
	require.NoError(err)
	var sessionTermReason []string
	var repoSessionId string
	for i := 0; i < len(repoSessions); i++ {
		s := repoSessions[i]
		repoSessionId = s.PublicId
		sessionTermReason = append(sessionTermReason, s.TerminationReason)
	}
	require.Equal([]string{"canceled"}, sessionTermReason)

	// Ensure connection is also cancelled
	connections, err := connectionRepo.ListConnectionsBySessionId(ctx, repoSessionId)
	require.NoError(err)

	var connTermReason []string
	for i := 0; i < len(connections); i++ {
		c := connections[i]
		connTermReason = append(connTermReason, c.ClosedReason)
	}
	require.Equal([]string{"canceled"}, connTermReason)

	// Validate new table contents
	rows, err := d.QueryContext(ctx, "select * from session_valid_state")
	require.NoError(err)

	var validStates []string
	for rows.Next() {
		var a, b string
		require.NoError(rows.Scan(&a, &b))
		validStates = append(validStates, []string{a, b}...)
	}
	require.Equal([]string{
		"pending", "pending", "pending", "active", "pending", "terminated",
		"pending", "canceling", "active", "canceling", "active", "terminated", "canceling", "terminated",
	}, validStates)
}
