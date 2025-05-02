package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

// cases to look at
// Global Role - Grant Descendants AND Children
// Global Role - Grant Descendants AND individual org
// Global Role - Grant Descendants AND individual project
// Global Role - Grant Children AND individual org
// Global Role - Grant Children AND individual project
// Org Role - Grant Children AND individual org (different org)
// Org Role - Grant Children AND individual project
// Org Role - Grant Children AND individual project (from different org)
// Project Role - Grant individual project (different proj)
func TestMigrationHook_FindIllegal(t *testing.T) {
	const (
		priorMigration = 95001
	)
	dialect := dbtest.Postgres
	ctx := context.Background()

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
	dbType, err := db.StringToDbType(dialect)
	require.NoError(t, err)
	conn, err := db.Open(ctx, dbType, u)
	rw := db.New(conn)

	t.Helper()

	query := `
	insert into iam_scope
	  (parent_id, type, public_id, name)
	values
	  ('global', 'org', 'o_testa__96001', 'Org A Testing Invalid Role Grant Scope Associations'),
	  ('global', 'org', 'o_testb__96001', 'Org B Testing Invalid Role Grant Scope Associations'),
	  `
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(t, err)

	query = `
	insert into iam_scope
	  (parent_id, type, public_id, name)
	values
	  ('o_testa__96001', 'project', 'p_PRJA___96001', 'testing 96001 Project A'),
	  ('o_testa__96001', 'project', 'p_PRJB___96001', 'testing 96001 Project B'),
	  ('o_testb__96001', 'project', 'p_PRJC___96001', 'testing 96001 Project C')`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(t, err)

	query = `
	insert into iam_role
	  (public_id, scope_id, name )
	values
	  ('r_globala_96001', 'global', 		'testing 96001 global role A'),
	  ('r_globalb_96001', 'global', 		'testing 96001 global role B'),
	  ('r_globalc_96001', 'global', 		'testing 96001 global role C'),
	  ('r_orgaa___96001', 'o_testa__96001', 'testing 96001 org A role A'),
	  ('r_orgab___96001', 'o_testb__96001', 'testing 96001 org A role B'),
	  ('r_globalb_96001', 'global', 'testing 96001 Project B'),
	  ('r_globala_96001', 'global', 'testing 96001 Project A'),
	  ('r_globalb_96001', 'global', 'testing 96001 Project B'),
	  ('r_globalc_96001', 'global', 'testing 96001 Project C')`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(t, err)

	query = `
	insert into iam_role_grant_scope
	  (role_id,	scope_id_or_special)
	values
	  ('o_testa__96001', 'project', 'p_PRJA___96001', 'testing 96001 Project A'),
	  ('o_testa__96001', 'project', 'p_PRJB___96001', 'testing 96001 Project B'),
	  ('o_testb__96001', 'project', 'p_PRJC___96001', 'testing 96001 Project C')`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(t, err)

}
