package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrations_user_password_Migration(t *testing.T) {
	const (
		priorMigration   = 31002
		currentMigration = 32001
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

	require.NoError(t, m.ApplyMigrations(ctx))
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

	// get a connection
	dbType, err := db.StringToDbType(dialect)
	require.NoError(t, err)
	conn, err := db.Open(ctx, dbType, u)
	require.NoError(t, err)
	rw := db.New(conn)

	rootWrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, rootWrapper)
	_, prj := iam.TestScopes(t, iamRepo)

	cs, err := vault.NewCredentialStore(prj.PublicId, "https://vault", []byte("token"))
	cs.PublicId = "csvlt_test1234"
	require.NoError(t, rw.Create(context.Background(), cs))

	upLib, err := vault.NewCredentialLibrary(cs.PublicId, "vault_path", vault.WithMethod("GET"), vault.WithCredentialType("user_password"))
	upLib.PublicId = "clvlt_testuplib"
	require.NoError(t, rw.Create(context.Background(), upLib))

	lib, err := vault.NewCredentialLibrary(cs.PublicId, "vault_path", vault.WithMethod("GET"))
	lib.PublicId = "clvlt_testlib"
	require.NoError(t, rw.Create(context.Background(), lib))

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(t, err)

	require.NoError(t, m.ApplyMigrations(ctx))
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

	// Validate uplib was migrated to username_password
	err = rw.LookupByPublicId(context.Background(), upLib)
	require.NoError(t, err)
	assert.Equal(t, "username_password", upLib.GetCredentialType())

	// Validate lib was left as unspecified
	err = rw.LookupByPublicId(context.Background(), lib)
	require.NoError(t, err)
	assert.Equal(t, "unspecified", lib.GetCredentialType())
}
