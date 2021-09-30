package migration

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/testing/dbtest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PrimaryAuthMethodChanges(t *testing.T) {
	t.Parallel()
	const priorMigration = 2006
	const primaryAuthMethodMigration = 2007
	t.Run("migrate-store", func(t *testing.T) {
		// this is a sequential test which relies on:
		// 1) initializing the db using a migration up to the "priorMigration"
		//
		// 2) seeding the database with some test scopes and auth methods
		//
		// 3) running the migrations that sets the primary auth methods for
		// existing scopes which only have one auth method.
		//
		// 4) asserting some bits about the state of the db.
		assert, require := assert.New(t), require.New(t)
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
		dbType, err := db.StringToDbType(dialect)
		require.NoError(err)
		conn, err := db.Open(dbType, u)
		require.NoError(err)
		rootWrapper := db.TestWrapper(t)
		iamRepo := iam.TestRepo(t, conn, rootWrapper)
		org, _ := iam.TestScopes(t, iamRepo)
		_ = password.TestAuthMethods(t, conn, org.PublicId, 3)
		org2, _ := iam.TestScopes(t, iamRepo)
		_ = password.TestAuthMethods(t, conn, org2.PublicId, 2)

		org3, _ := iam.TestScopes(t, iamRepo)
		org3AuthMethods := password.TestAuthMethods(t, conn, org3.PublicId, 1)
		org4, _ := iam.TestScopes(t, iamRepo)
		org4AuthMethods := password.TestAuthMethods(t, conn, org4.PublicId, 1)

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

		t.Log("current migration version: ", state.DatabaseSchemaVersion)
		entries, err := schema.GetMigrationLog(ctx, d)
		require.NoError(err)
		for _, e := range entries {
			t.Logf("%+v", e)
		}
		assert.Equalf(2, len(entries), "expected 2 scopes without a primary auth method and got: %d", len(entries))

		scope1, err := iamRepo.LookupScope(ctx, org.PublicId)
		require.NoError(err)
		assert.Empty(scope1.PrimaryAuthMethodId)
		scope2, err := iamRepo.LookupScope(ctx, org2.PublicId)
		require.NoError(err)
		assert.Empty(scope2.PrimaryAuthMethodId)

		scope3, err := iamRepo.LookupScope(ctx, org3.PublicId)
		require.NoError(err)
		assert.Equal(org3AuthMethods[0].PublicId, scope3.PrimaryAuthMethodId)

		scope4, err := iamRepo.LookupScope(ctx, org4.PublicId)
		require.NoError(err)
		assert.Equal(org4AuthMethods[0].PublicId, scope4.PrimaryAuthMethodId)
	})
}
