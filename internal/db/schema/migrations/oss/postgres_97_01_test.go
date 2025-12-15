// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/db/schema/internal/postgres"
	"github.com/hashicorp/boundary/internal/db/schema/migration"
	"github.com/hashicorp/boundary/internal/db/schema/migrations/oss/internal/hook97001"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

// cases to look at [NA = not-applicable | P = pass | F = fail] - 'FindProblem' query should find all `F` cases
// [F] Global Role (r_globala_97001) - Grant This, Descendants, individual org, and individual project
//   - need to remove individual org
//   - need to remove individual proj
//
// [F] Global Role (r_globalb_97001) - Grant This, Children, individual org, and individual project
//   - need to remove individual org
//
// [P] Global Role (r_globalc_97001) - Grant role's self scope ID
//   - switch to `this` automagically
//
// [F] Org Role (r_orgaa___97001) - Grant This, Children, and individual project
//   - need to remove individual project
//
// [P] Org Role (r_orgab___97001) - Grant role self scope ID
//   - switch to `this` automagically
//
// [P] Project Role (r_prjaa___97001) - Grant self scope ID
//   - switch to `this` automagically
//
// [NA] Org Role - Grant Children AND individual org (different org)
//   - this cannot be created
//
// [NA] Org Role - Grant Children AND individual project (from different org)
//   - this cannot be created
//
// [NA] Project Role (p_pA___97001) - Grant individual project (different proj)
//   - this cannot be created
//
// [NA] Global Role - Grant Descendants and Children
//   - this cannot be created
func TestMigrationHook97001(t *testing.T) {
	const (
		priorMigration  = 95001
		latestMigration = 97005
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
	require.NoError(t, err)
	rw := db.New(conn)

	t.Helper()

	query := `
	insert into iam_scope
	  (parent_id, type, public_id, name)
	values
	  ('global', 'org', 'o_ta___97001', 'Org A Testing Invalid Role Grant Scope Associations'),
	  ('global', 'org', 'o_tb___97001', 'Org B Testing Invalid Role Grant Scope Associations'),
	  ('o_ta___97001', 'project', 'p_pA___97001', 'testing 97001 Project A'),
	  ('o_ta___97001', 'project', 'p_pB___97001', 'testing 97001 Project B'),
	  ('o_tb___97001', 'project', 'p_pC___97001', 'testing 97001 Project C')`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(t, err)

	query = `
	insert into iam_role
	  (public_id, scope_id, name )
	values
	  ('r_globala_97001', 'global', 		'testing 97001 global role A'),
	  ('r_globalb_97001', 'global', 		'testing 97001 global role B'),
 	  ('r_globalc_97001', 'global', 		'testing 97001 global role C'),
 	  ('r_globald_97001', 'global', 		'testing 97001 global role D'),
 	  ('r_globale_97001', 'global', 		'testing 97001 global role E'),
 	  ('r_globalf_97001', 'global', 		'testing 97001 global role f'),
	  ('r_orgaa___97001', 'o_ta___97001', 	'testing 97001 org A role A'),
	  ('r_orgab___97001', 'o_ta___97001', 	'testing 97001 org A role B'),
	  ('r_prjaa___97001', 'p_pA___97001', 	'testing 97001 proj A role A'),
	  ('r_prjab___97001', 'p_pA___97001', 	'testing 97001 proj A role B')
	  `
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(t, err)

	query = `
	insert into iam_role_grant_scope
	  (role_id,	scope_id_or_special)
	values
	   -- Global Role (r_globala_97001) - Grant This, Descendants, individual org, and individual project
	  ('r_globala_97001', 'this'),
	  ('r_globala_97001', 'descendants'),
	  ('r_globala_97001', 'o_ta___97001'),
	  ('r_globala_97001', 'p_pA___97001'),
  	   -- Global Role (r_globalb_97001) - Grant This, Children, individual org, and individual project
	  ('r_globalb_97001', 'this'),
	  ('r_globalb_97001', 'children'),
	  ('r_globalb_97001', 'o_ta___97001'),
	  ('r_globalb_97001', 'p_pA___97001'),
	  -- Org Role (r_orgaa___97001) - Grant This, Children, and individual project
 	  ('r_orgaa___97001', 'this'),
 	  ('r_orgaa___97001', 'children'),
	  ('r_orgaa___97001', 'p_pA___97001'),
	  -- below this line are non-problematic roles that should not show up in the final list
	  -- Global Role (r_globalc_97001) - Grant role's self scope ID
	  ('r_globalc_97001', 'global'),
	  -- Global Role (r_globald_97001) - Grant children and project
	  ('r_globald_97001', 'children'),
	  ('r_globald_97001', 'p_pA___97001'),
	  -- Global Role (r_globale_97001) - Grant this and descendants
	  ('r_globale_97001', 'this'),
	  ('r_globale_97001', 'descendants'),
  	  -- Global Role (r_globalf_97001) - Grant this and children
	  ('r_globalf_97001', 'this'),
	  ('r_globalf_97001', 'children'),
	  -- Org Role (r_orgab___97001) - Grant role self scope ID
 	  ('r_orgab___97001', 'o_ta___97001'),
	  -- Project Role (p_pA___97001) - Grant self scope ID
 	  ('r_prjaa___97001', 'p_pA___97001')
	`
	_, err = rw.Exec(ctx, query, nil)
	require.NoError(t, err)

	// migrate to latest - make sure it fails
	// migration to the prior migration (before the one we want to test)
	latestm, err := schema.NewManager(ctx, schema.Dialect(dialect), d)
	require.NoError(t, err)
	_, err = latestm.ApplyMigrations(ctx)
	require.Error(t, err)

	driver, err := postgres.New(ctx, d)
	require.NoError(t, err)
	schemaVer, _, err := driver.CurrentState(ctx, "oss")
	require.NoError(t, err)
	require.Equal(t, priorMigration, schemaVer)

	tx, err := d.BeginTx(ctx, nil)
	require.NoError(t, err)

	// Run hook check
	checkReport, err := hook97001.FindInvalidAssociations(ctx, tx)
	require.NoError(t, err)

	// Run hook repair
	repairReport, err := hook97001.RepairInvalidAssociations(ctx, tx)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	hook97001validateCheckFunc(t, checkReport)
	hook97001validateRepairFunc(t, repairReport)
}

func hook97001validateCheckFunc(t *testing.T, checkReport migration.Problems) {
	t.Helper()
	require := require.New(t)
	require.ElementsMatch(checkReport, migration.Problems{
		"Role 'r_globala_97001' in scope 'global' has the 'descendants' grant scope which covers 'o_ta___97001'",
		"Role 'r_globala_97001' in scope 'global' has the 'descendants' grant scope which covers 'p_pA___97001'",
		"Role 'r_globalb_97001' in scope 'global' has the 'children' grant scope which covers 'o_ta___97001'",
		"Role 'r_orgaa___97001' in scope 'o_ta___97001' has the 'children' grant scope which covers 'p_pA___97001'",
	})
}

func hook97001validateRepairFunc(t *testing.T, checkReport migration.Repairs) {
	t.Helper()
	require := require.New(t)
	require.ElementsMatch(checkReport, migration.Problems{
		"Remove redundant grant scopes 'o_ta___97001' association from role 'r_globala_97001' in scope 'global' because it overlaps with 'descendants'",
		"Remove redundant grant scopes 'p_pA___97001' association from role 'r_globala_97001' in scope 'global' because it overlaps with 'descendants'",
		"Remove redundant grant scopes 'o_ta___97001' association from role 'r_globalb_97001' in scope 'global' because it overlaps with 'children'",
		"Remove redundant grant scopes 'p_pA___97001' association from role 'r_orgaa___97001' in scope 'o_ta___97001' because it overlaps with 'children'",
	})
}
