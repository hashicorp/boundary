package migration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/docker"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PrimaryAuthMethodChanges(t *testing.T) {
	t.Parallel()
	const priorMigration = 2086
	const primaryAuthMethodMigration = 2087
	t.Run("migrate-store", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		dialect := "postgres"
		ctx := context.Background()

		c, u, _, err := docker.StartDbInDocker(dialect)
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

		// okay, now we can seed the database with test data
		conn, err := gorm.Open(dialect, u)
		require.NoError(err)
		rootWrapper := db.TestWrapper(t)
		iamRepo := iam.TestRepo(t, conn, rootWrapper)
		org, _ := iam.TestScopes(t, iamRepo)
		_ = password.TestAuthMethods(t, conn, org.PublicId, 3)
		org2, _ := iam.TestScopes(t, iamRepo)
		_ = password.TestAuthMethods(t, conn, org2.PublicId, 2)

		org3, _ := iam.TestScopes(t, iamRepo)
		_ = password.TestAuthMethods(t, conn, org3.PublicId, 1)
		org4, _ := iam.TestScopes(t, iamRepo)
		_ = password.TestAuthMethods(t, conn, org4.PublicId, 1)

		// now we're ready for the migration we want to test.
		oState = schema.TestCloneMigrationStates(t)
		nState = schema.TestCreatePartialMigrationState(oState["postgres"], primaryAuthMethodMigration)
		oState["postgres"] = nState

		m, err = schema.NewManager(ctx, dialect, d, schema.WithMigrationStates(oState))
		require.NoError(err)

		assert.NoError(m.RollForward(ctx))
		state, err = m.CurrentState(ctx)
		require.NoError(err)
		assert.Equal(primaryAuthMethodMigration, state.DatabaseSchemaVersion)
		assert.False(state.Dirty)

		entries := getMigrationLog(t, d)
		for _, e := range entries {
			t.Log(e)
		}
		assert.Equalf(2, len(entries), "expected 2 scopes without a primary auth method and got: ", len(entries))
	})
}

type logEntry struct {
	Id               int
	MigrationVersion string
	Entry            string
}

func getMigrationLog(t *testing.T, d *sql.DB) []logEntry {
	t.Helper()
	require := require.New(t)
	const sql = "select id, migration_version, entry from log_migration"
	ctx := context.Background()
	rows, err := d.QueryContext(ctx, sql)
	require.NoError(err)
	defer rows.Close()

	var entries []logEntry
	for rows.Next() {
		var e logEntry
		require.NoError(rows.Scan(&e.Id, &e.MigrationVersion, &e.Entry))
		entries = append(entries, e)
	}
	require.NoError(rows.Err())
	return entries
}
