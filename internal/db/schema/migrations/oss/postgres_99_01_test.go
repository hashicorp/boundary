package oss_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/targettest"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

const (
	insertTargetQuery = `INSERT INTO "target_tcp" ("public_id","project_id","name","session_max_seconds","session_connection_limit","worker_filter") VALUES ($1,$2,$3,28800,-1,$4)`
)

func TestMigrations_AddEgressAndIngressFilters(t *testing.T) {
	const (
		priorMigration   = 58001
		currentMigration = 99001
	)

	t.Parallel()
	ctx := context.Background()
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	// migration to the prior migration (before the one we want to test)
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": priorMigration}),
	))
	require.NoError(t, err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(t, err)
	state, err := m.CurrentState(ctx)
	require.NoError(t, err)
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
	require.Equal(t, want, state)

	// Get a connection
	dbType, err := db.StringToDbType(dialect)
	require.NoError(t, err)
	conn, err := db.Open(ctx, dbType, u)
	require.NoError(t, err)

	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	err = kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)

	// Create a target with a worker filter
	oldTargetId1, err := db.NewPublicId("ttcp")
	oldWorkerFilter := "foo==bar"
	require.NoError(t, err)
	execResult, err := d.ExecContext(ctx, insertTargetQuery, oldTargetId1, proj.PublicId, "old-target-1", oldWorkerFilter)
	require.NoError(t, err)
	rowsAffected, err := execResult.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), rowsAffected)

	// Create another target with a worker filter to use in testing
	oldTargetId2, err := db.NewPublicId("ttcp")
	require.NoError(t, err)
	execResult, err = d.ExecContext(ctx, insertTargetQuery, oldTargetId2, proj.PublicId, "old-target-2", oldWorkerFilter)
	require.NoError(t, err)
	rowsAffected, err = execResult.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), rowsAffected)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(t, err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(t, err)
	state, err = m.CurrentState(ctx)
	require.NoError(t, err)
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
	require.Equal(t, want, state)

	testRepo, err := target.NewRepository(ctx, rw, rw, kmsCache)

	// Ensure old target 1 still have the same worker filter
	result, _, _, err := testRepo.LookupTarget(ctx, oldTargetId1)
	require.Equal(t, oldWorkerFilter, result.GetWorkerFilter())

	// Update the old worker filter
	newWorkerFilter := "bar==foo"
	result.SetWorkerFilter(newWorkerFilter)
	result, _, _, _, err = testRepo.UpdateTarget(ctx, result, result.GetVersion(), []string{"WorkerFilter"})
	require.Equal(t, newWorkerFilter, result.GetWorkerFilter())

	// Update to set an egress filter- expect worker filter to be cleared out
	result.SetEgressWorkerFilter(newWorkerFilter)
	result, _, _, _, err = testRepo.UpdateTarget(ctx, result, result.GetVersion(), []string{"EgressWorkerFilter"})
	require.Equal(t, newWorkerFilter, result.GetEgressWorkerFilter())
	require.Empty(t, result.GetWorkerFilter())

	// Attempt to set worker filter again - expect failure
	result.SetWorkerFilter(newWorkerFilter)
	result, _, _, _, err = testRepo.UpdateTarget(ctx, result, result.GetVersion(), []string{"WorkerFilter"})
	require.Error(t, err)

	// Ensure old target 2 still has the same worker filter
	result, _, _, err = testRepo.LookupTarget(ctx, oldTargetId2)
	require.Equal(t, oldWorkerFilter, result.GetWorkerFilter())

	// Clear out its worker filter
	result.SetWorkerFilter("")
	result, _, _, _, err = testRepo.UpdateTarget(ctx, result, result.GetVersion(), []string{"WorkerFilter"})
	require.Equal(t, "", result.GetWorkerFilter())

	// Update to set an ingress filter- expect worker filter to be cleared out
	result.SetIngressWorkerFilter(newWorkerFilter)
	result, _, _, _, err = testRepo.UpdateTarget(ctx, result, result.GetVersion(), []string{"IngressWorkerFilter"})
	require.Equal(t, newWorkerFilter, result.GetIngressWorkerFilter())
	require.Empty(t, result.GetWorkerFilter())

	// Attempt to create a new target with a worker filter- expect failure
	tar, err := targettest.New(proj.PublicId, target.WithName("new-worker"), target.WithWorkerFilter(oldWorkerFilter))
	require.NoError(t, err)
	id, err := db.NewPublicId("ttcp")
	require.NoError(t, err)
	tar.SetPublicId(ctx, id)
	err = rw.Create(context.Background(), tar)
	require.Error(t, err)

	// Create a new target with egress and ingress filters
	tar2, err := targettest.New(proj.PublicId, target.WithName("new-worker-filters"), target.WithEgressWorkerFilter(oldWorkerFilter),
		target.WithIngressWorkerFilter(oldWorkerFilter))
	require.NoError(t, err)
	id, err = db.NewPublicId("ttcp")
	require.NoError(t, err)
	tar2.SetPublicId(ctx, id)
	err = rw.Create(context.Background(), tar2)
	require.NoError(t, err)

	// Attempt to create a new target with all 3 filters- expect failure
	tar3, err := targettest.New(proj.PublicId, target.WithName("new-worker-filters"), target.WithEgressWorkerFilter(oldWorkerFilter),
		target.WithIngressWorkerFilter(oldWorkerFilter), target.WithEgressWorkerFilter(oldWorkerFilter))
	require.NoError(t, err)
	id, err = db.NewPublicId("ttcp")
	require.NoError(t, err)
	tar3.SetPublicId(ctx, id)
	err = rw.Create(context.Background(), tar3)
	require.Error(t, err)
}
