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

func TestMigrations_SessionFKeyDelete(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	const (
		priorMigration   = 28002
		currentMigration = 29001
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
	targetRepo, err := target.NewRepository(rw, rw, kmsCache)
	require.NoError(err)

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

	// Create and terminate session without canceling
	_, _, err = sessionRepo.ActivateSession(ctx, sess.PublicId, sess.Version, serverId, resource.Worker.String(), tofu)
	require.NoError(err)
	session.TestState(t, conn, sess.PublicId, session.StatusTerminated)

	// Delete target; expect a session_state violation and failure to delete target
	rows, err := targetRepo.DeleteTarget(ctx, tar.GetPublicId())
	require.Errorf(err, "target.(Repository).DeleteTarget: db.DoTx: target.(Repository).DeleteTarget: db.Delete: insert or update on table \"session_state\" violates foreign key constraint \"session_valid_state_enm_fkey\": integrity violation: error #1003")
	require.Equal(0, rows)

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

	// Try to delete target again, should succeed without error
	rows, err = targetRepo.DeleteTarget(ctx, tar.GetPublicId())
	require.NoError(err)
	require.Equal(1, rows)
}
