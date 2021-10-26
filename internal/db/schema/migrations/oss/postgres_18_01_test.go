package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrations_ServerNonce(t *testing.T) {
	const (
		priorMigration   = 16005
		currentMigration = 17001
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

	// get a connection
	dbType, err := db.StringToDbType(dialect)
	require.NoError(err)
	conn, err := db.Open(dbType, u)
	require.NoError(err)
	rw := db.New(conn)

	// okay, now we can seed the database with test data and validate existing
	// functionality. At the end of this we will have two values in the table
	// with no purpose.
	{
		// Create an old version of the struct
		type RecoveryNonce struct {
			Nonce string
		}

		require.NoError(rw.CreateItems(ctx, []interface{}{
			&RecoveryNonce{Nonce: "abcd"},
			&RecoveryNonce{Nonce: "dcba"},
		}))

		var results []*RecoveryNonce
		require.NoError(rw.SearchWhere(ctx, &results, "", nil))
		require.Len(results, 2)
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

	// now we have migrated and we will validate functionality; we'll do this
	// via the repo
	{
		wrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrapper)
		rw := db.New(conn)
		repo, err := servers.NewRepository(rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		// First list and validate that the upgrade adjusted purpose correctly
		results, err := repo.ListNonces(ctx, servers.NoncePurposeRecovery)
		require.NoError(err)
		assert.Len(results, 2)
		for _, n := range results {
			assert.Equal(servers.NoncePurposeRecovery, n.Purpose)
		}

		// Test the constraint, first via the repo, then directly
		const badPurpose = "foobar"
		err = repo.AddNonce(ctx, "xyz", badPurpose)
		require.Error(err)
		assert.Contains(err.Error(), "unknown nonce purpose")

		// Check that null errors
		require.Error(rw.CreateItems(ctx, []interface{}{
			&servers.ServerNonce{Nonce: "dcba"},
		}))
		// Check that bad purpose errors
		require.Error(rw.CreateItems(ctx, []interface{}{
			&servers.ServerNonce{Nonce: "dcba", Purpose: badPurpose},
		}))

		// Add some valid values, ensure that we can then list for both purposes
		// and get different values
		require.NoError(repo.AddNonce(ctx, "wxyz", servers.NoncePurposeWorkerAuth))
		require.NoError(repo.AddNonce(ctx, "zyxw", servers.NoncePurposeWorkerAuth))
		results, err = repo.ListNonces(ctx, servers.NoncePurposeRecovery)
		require.NoError(err)
		assert.Len(results, 2)
		for _, n := range results {
			assert.Equal(servers.NoncePurposeRecovery, n.Purpose)
		}
		results, err = repo.ListNonces(ctx, servers.NoncePurposeWorkerAuth)
		require.NoError(err)
		assert.Len(results, 2)
		for _, n := range results {
			assert.Equal(servers.NoncePurposeWorkerAuth, n.Purpose)
		}

		// Last: add the same nonce, ensure we error
		require.NoError(repo.AddNonce(ctx, "double", servers.NoncePurposeWorkerAuth))
		err = repo.AddNonce(ctx, "double", servers.NoncePurposeWorkerAuth)
		require.Error(err)
		require.Contains(err.Error(), "duplicate key value")
	}
}
