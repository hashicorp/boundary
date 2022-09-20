package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

func TestMigrations_NewForeignKeys(t *testing.T) {
	const (
		priorMigration   = 55001
		currentMigration = 55002
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

	// Create project
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)

	// Create a session
	sess := session.TestSession(t, conn, wrapper, session.TestSessionParams(t, conn, wrapper, iamRepo))
	_ = sess

	// Create a password account
	pwam := password.TestAuthMethod(t, conn, "global")
	password.TestAccount(t, conn, pwam.PublicId, "user", password.WithPassword("password"))

	// Create an auth token
	tok := authtoken.TestAuthToken(t, conn, kmsCache, "global")
	_ = tok

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

	// As long as there were no errors, the migration succeeded.
}
