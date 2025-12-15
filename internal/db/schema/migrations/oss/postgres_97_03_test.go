// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/db/schema/migrations/oss/internal/hook97001"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
)

type testRole struct {
	role_id               string
	scope_id              string
	name                  string
	description           string
	version               uint32
	grant_this_role_scope bool
	grant_scope           string
}

const (
	selectGlobalRoleQuery = `
    select
        public_id,
        scope_id,
        name,
        description,
        version,
        grant_this_role_scope,
        grant_scope
    from iam_role_global;
    `
	selectOrgRoleQuery = `
    select
        public_id,
        scope_id,
        name,
        description,
        version,
        grant_this_role_scope,
        grant_scope
    from iam_role_org;
    `
	selectProjectRoleQuery = `
    select
        public_id,
        scope_id,
        name,
        description,
        version,
        grant_this_role_scope
    from iam_role_project;
    `
	selectGlobalIndividualOrgGrantScopeQuery = `
    select
        role_id,
        scope_id,
        grant_scope
    from iam_role_global_individual_org_grant_scope;
    `
	selectGlobalIndividualProjectGrantScopeQuery = `
    select
        role_id,
        scope_id,
        grant_scope
    from iam_role_global_individual_project_grant_scope;
    `
	selectOrgIndividualGrantScopeQuery = `
    select
        role_id,
        scope_id,
        grant_scope
    from iam_role_org_individual_grant_scope;
    `
	selectCountSubTableRolesQuery = `
    select (
        (select count(*) from iam_role_global where grant_this_role_scope = true) +
        (select count(*) from iam_role_global where grant_scope != 'individual') +
        (select count(*) from iam_role_org where grant_this_role_scope = true) +
        (select count(*) from iam_role_org where grant_scope != 'individual') +
        (select count(*) from iam_role_project where grant_this_role_scope = true) +
        (select count(*) from iam_role_global_individual_org_grant_scope) +
        (select count(*) from iam_role_global_individual_project_grant_scope) +
        (select count(*) from iam_role_org_individual_grant_scope)
    ) as total_count;
    `
)

func Test_IamRoleAndGrantScopeMigration(t *testing.T) {
	require := require.New(t)
	dialect := dbtest.Postgres
	ctx := context.Background()

	priorMigration := 96001
	currentMigration := 97005

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

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	// Seed the data
	insertScopes := `
    insert into iam_scope
      (parent_id,      type,      public_id,      name)
    values
      ('global',       'org',     'o_____colors', 'Colors R Us'),
      ('o_____colors', 'project', 'p____bcolors', 'Blue Color Mill'),
      ('o_____colors', 'project', 'p____rcolors', 'Red Color Mill'),
      ('o_____colors', 'project', 'p____gcolors', 'Green Color Mill'),
      ('global',       'org',     'o_ta____test', 'Org A Testing Role Grant Scope Migrations'),
      ('global',       'org',     'o_tb____test', 'Org B Testing Role Grant Scope Migrations'),
      ('o_ta____test', 'project', 'p_pA____test', 'Migration test Project A'),
      ('o_ta____test', 'project', 'p_pB____test', 'Migration test Project B'),
      ('o_tb____test', 'project', 'p_pC____test', 'Migration test Project C');
    `
	_, err = d.ExecContext(ctx, insertScopes)
	require.NoError(err)

	insertRoles := `
    insert into iam_role
      (scope_id,       public_id,         name,                           description,                    version,    create_time,               update_time)
    values
      ('p____bcolors', 'r_pp_bc__mix',    'Color Mixer',                  'Mixes blue colors',            1,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('p____rcolors', 'r_pp_rc__mix',    'Color Mixer',                  'Mixes red colors',             2,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('p____gcolors', 'r_pp_gc__mix',    'Color Mixer',                  'Mixes green colors',           3,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('o_____colors', 'r_op_bc__art',    'Blue Color Artist',            'Creates blue colors',          4,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('o_____colors', 'r_op_rc__art',    'Red Color Artist',             'Creates red colors',           5,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('o_____colors', 'r_op_gc__art',    'Green Color Artist',           'Creates green colors',         6,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('o_____colors', 'r_oo_____art',    'Color Artist',                 'Creates colors',               7,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
            ('global', 'r_go____name',    'Color Namer',                  'Names colors',                 8,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
            ('global', 'r_gp____spec',    'Blue Color Inspector',         'Inspects blue colors',         9,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
            ('global', 'r_gg_____buy',    'Purchaser',                    'Buys colors',                  10,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
            ('global', 'r_gg____shop',    'Shopper',                      'Shops for colors',             11,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
            ('global', 'r_globala__test', 'Migration test global role A', 'Migration test global role A', 12,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
            ('global', 'r_globalb__test', 'Migration test global role B', 'Migration test global role B', 13,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
            ('global', 'r_globalc__test', 'Migration test global role C', 'Migration test global role C', 14,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
            ('global', 'r_globald__test', 'Migration test global role D', 'Migration test global role D', 15,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
            ('global', 'r_globale__test', 'Migration test global role E', 'Migration test global role E', 16,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
            ('global', 'r_globalf__test', 'Migration test global role f', 'Migration test global role f', 17,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('o_ta____test', 'r_orgaa____test', 'Migration test org A role A',  'Migration test org A role A',  18,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('o_ta____test', 'r_orgab____test', 'Migration test org A role B',  'Migration test org A role B',  19,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('p_pA____test', 'r_prjaa____test', 'Migration test proj A role A', 'Migration test proj A role A', 20,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('p_pA____test', 'r_prjab____test', 'Migration test proj A role B', 'Migration test proj A role B', 21,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoles)
	require.NoError(err)

	insertRoleGrantScopes := `
    insert into iam_role_grant_scope
      (role_id,          scope_id_or_special,   create_time)
    values
      ('r_pp_bc__mix',    'this',               '2025-03-01 16:43:15.489'),
      ('r_pp_rc__mix',    'p____rcolors',       '2025-03-02 16:43:15.489'),
      ('r_pp_gc__mix',    'this',               '2025-03-03 16:43:15.489'),
      ('r_op_bc__art',    'p____bcolors',       '2025-03-04 16:43:15.489'),
      ('r_op_bc__art',    'children',           '2025-03-05 16:43:15.489'),
      ('r_op_rc__art',    'p____rcolors',       '2025-03-06 16:43:15.489'),
      ('r_op_gc__art',    'p____gcolors',       '2025-03-07 16:43:15.489'),
      ('r_go____name',    'o_____colors',       '2025-03-08 16:43:15.489'),
      ('r_gp____spec',    'p____bcolors',       '2025-03-09 16:43:15.489'),
      ('r_gg_____buy',    'descendants',        '2025-03-01 16:43:15.489'),
      ('r_gg____shop',    'global',             '2025-03-02 16:43:15.489'),
      ('r_gg____shop',    'children',           '2025-03-03 16:43:15.489'),
      ('r_globala__test', 'this',               '2025-03-01 16:43:15.489'),
      ('r_globala__test', 'descendants',        '2025-03-01 16:43:15.489'),
      ('r_globala__test', 'o_ta____test',       '2025-03-01 16:43:15.489'),
      ('r_globala__test', 'p_pA____test',       '2025-03-01 16:43:15.489'),
      ('r_globalb__test', 'this',               '2025-03-01 16:43:15.489'),
      ('r_globalb__test', 'children',           '2025-03-01 16:43:15.489'),
      ('r_globalb__test', 'o_ta____test',       '2025-03-01 16:43:15.489'),
      ('r_globalb__test', 'p_pA____test',       '2025-03-01 16:43:15.489'),
      ('r_orgaa____test', 'o_ta____test',       '2025-03-01 16:43:15.489'),
      ('r_orgaa____test', 'children',           '2025-03-01 16:43:15.489'),
      ('r_orgaa____test', 'p_pA____test',       '2025-03-01 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoleGrantScopes)
	require.NoError(err)

	insertRoleGrants := `
    insert into iam_role_grant
      (role_id,        canonical_grant,                                    raw_grant)
    values
      ('r_gg_____buy', 'ids=*;type=*;actions=update',                      'ids=*;type=*;actions=update'),
      ('r_gg____shop', 'ids=*;type=*;actions=read;output_fields=id',       'ids=*;type=*;actions=read;output_fields=id'),
      ('r_go____name', 'ids=*;type=group;actions=create,update,read,list', 'ids=*;type=group;actions=create,update,read,list'),
      ('r_gp____spec', 'ids=*;type=group;actions=delete',                  'ids=*;type=group;actions=delete'),
      ('r_oo_____art', 'ids=*;type=group;actions=create',                  'ids=*;type=group;actions=create'),
      ('r_op_bc__art', 'ids=*;type=auth-token;actions=create',             'ids=*;type=auth-token;actions=create'),
      ('r_op_rc__art', 'ids=*;type=target;actions=create',                 'ids=*;type=targets;actions=create'),
      ('r_op_gc__art', 'ids=*;type=auth-method;actions=authenticate',      'ids=*;type=auth-method;actions=create'),
      ('r_pp_bc__mix', 'ids=*;type=group;actions=add-members',             'ids=*;type=group;actions=add-members'),
      ('r_pp_rc__mix', 'ids=*;type=group;actions=set-members',             'ids=*;type=group;actions=set-members'),
      ('r_pp_gc__mix', 'ids=*;type=group;actions=delete-members',          'ids=*;type=group;actions=delete-members');
    `
	_, err = d.ExecContext(ctx, insertRoleGrants)
	require.NoError(err)

	tx, err := d.BeginTx(ctx, nil)
	require.NoError(err)

	// Run hook check
	_, err = hook97001.FindInvalidAssociations(ctx, tx)
	require.NoError(err)

	// Run hook repair
	_, err = hook97001.RepairInvalidAssociations(ctx, tx)
	require.NoError(err)

	err = tx.Commit()
	require.NoError(err)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	t.Run("iam_role_global migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalRoleQuery)
		require.NoError(err)
		globalRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			globalRoles = append(globalRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(globalRoles, 10)
		require.Equal([]testRole{
			{
				role_id:               "r_go____name",
				scope_id:              "global",
				name:                  "Color Namer",
				description:           "Names colors",
				version:               8,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
			{
				role_id:               "r_gp____spec",
				scope_id:              "global",
				name:                  "Blue Color Inspector",
				description:           "Inspects blue colors",
				version:               9,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
			{
				role_id:               "r_gg_____buy",
				scope_id:              "global",
				name:                  "Purchaser",
				description:           "Buys colors",
				version:               10,
				grant_this_role_scope: false,
				grant_scope:           "descendants",
			},
			{
				role_id:               "r_gg____shop",
				scope_id:              "global",
				name:                  "Shopper",
				description:           "Shops for colors",
				version:               11,
				grant_this_role_scope: true,
				grant_scope:           "children",
			},
			{
				role_id:               "r_globala__test",
				scope_id:              "global",
				name:                  "Migration test global role A",
				description:           "Migration test global role A",
				version:               12,
				grant_this_role_scope: true,
				grant_scope:           "descendants",
			},
			{
				role_id:               "r_globalb__test",
				scope_id:              "global",
				name:                  "Migration test global role B",
				description:           "Migration test global role B",
				version:               13,
				grant_this_role_scope: true,
				grant_scope:           "children",
			},
			{
				role_id:               "r_globalc__test",
				scope_id:              "global",
				name:                  "Migration test global role C",
				description:           "Migration test global role C",
				version:               14,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
			{
				role_id:               "r_globald__test",
				scope_id:              "global",
				name:                  "Migration test global role D",
				description:           "Migration test global role D",
				version:               15,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
			{
				role_id:               "r_globale__test",
				scope_id:              "global",
				name:                  "Migration test global role E",
				description:           "Migration test global role E",
				version:               16,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
			{
				role_id:               "r_globalf__test",
				scope_id:              "global",
				name:                  "Migration test global role f",
				description:           "Migration test global role f",
				version:               17,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
		}, globalRoles)
	})

	t.Run("iam_role_org migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgRoleQuery)
		require.NoError(err)
		orgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			orgRoles = append(orgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(orgRoles, 6)
		require.Equal([]testRole{
			{
				role_id:               "r_op_bc__art",
				scope_id:              "o_____colors",
				name:                  "Blue Color Artist",
				description:           "Creates blue colors",
				version:               4,
				grant_this_role_scope: false,
				grant_scope:           "children",
			},
			{
				role_id:               "r_op_rc__art",
				scope_id:              "o_____colors",
				name:                  "Red Color Artist",
				description:           "Creates red colors",
				version:               5,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
			{
				role_id:               "r_op_gc__art",
				scope_id:              "o_____colors",
				name:                  "Green Color Artist",
				description:           "Creates green colors",
				version:               6,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
			{
				role_id:               "r_orgaa____test",
				scope_id:              "o_ta____test",
				name:                  "Migration test org A role A",
				description:           "Migration test org A role A",
				version:               18,
				grant_this_role_scope: false,
				grant_scope:           "children",
			},
			{
				role_id:               "r_oo_____art",
				scope_id:              "o_____colors",
				name:                  "Color Artist",
				description:           "Creates colors",
				version:               7,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
			{
				role_id:               "r_orgab____test",
				scope_id:              "o_ta____test",
				name:                  "Migration test org A role B",
				description:           "Migration test org A role B",
				version:               19,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
		}, orgRoles)
	})

	t.Run("iam_role_project migration", func(t *testing.T) {
		rows, err := d.Query(selectProjectRoleQuery)
		require.NoError(err)
		projRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
			))
			projRoles = append(projRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(projRoles, 5)
		require.Equal([]testRole{
			{
				role_id:               "r_prjaa____test",
				scope_id:              "p_pA____test",
				name:                  "Migration test proj A role A",
				description:           "Migration test proj A role A",
				version:               20,
				grant_this_role_scope: false,
			},
			{
				role_id:               "r_prjab____test",
				scope_id:              "p_pA____test",
				name:                  "Migration test proj A role B",
				description:           "Migration test proj A role B",
				version:               21,
				grant_this_role_scope: false,
			},
			{
				role_id:               "r_pp_bc__mix",
				scope_id:              "p____bcolors",
				name:                  "Color Mixer",
				description:           "Mixes blue colors",
				version:               1,
				grant_this_role_scope: true,
			},
			{
				role_id:               "r_pp_rc__mix",
				scope_id:              "p____rcolors",
				name:                  "Color Mixer",
				description:           "Mixes red colors",
				version:               2,
				grant_this_role_scope: true,
			},
			{
				role_id:               "r_pp_gc__mix",
				scope_id:              "p____gcolors",
				name:                  "Color Mixer",
				description:           "Mixes green colors",
				version:               3,
				grant_this_role_scope: true,
			},
		}, projRoles)
	})

	t.Run("iam_role_global_individual_org_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualOrgGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(individualOrgRoles, 1)
		require.Equal([]testRole{
			{
				role_id:     "r_go____name",
				scope_id:    "o_____colors",
				grant_scope: "individual",
			},
		}, individualOrgRoles)
	})

	t.Run("iam_role_global_individual_proj_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualProjectGrantScopeQuery)
		require.NoError(err)
		individualProjRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualProjRoles = append(individualProjRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(individualProjRoles, 2)
		require.Equal([]testRole{
			{
				role_id:     "r_gp____spec",
				scope_id:    "p____bcolors",
				grant_scope: "individual",
			},
			{
				role_id:     "r_globalb__test",
				scope_id:    "p_pA____test",
				grant_scope: "children",
			},
		}, individualProjRoles)
	})

	t.Run("iam_role_org_individual_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgIndividualGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(individualOrgRoles, 2)
		require.Equal([]testRole{
			{
				role_id:     "r_op_rc__art",
				scope_id:    "p____rcolors",
				grant_scope: "individual",
			},
			{
				role_id:     "r_op_gc__art",
				scope_id:    "p____gcolors",
				grant_scope: "individual",
			},
		}, individualOrgRoles)
	})

	t.Run("compare prior and new table counts", func(t *testing.T) {
		// the number of sub-table roles should be the same
		// as the original iam_role_grant_scope table (17)
		var count int
		row := d.QueryRowContext(ctx, selectCountSubTableRolesQuery)
		require.NoError(row.Scan(&count))
		require.Equal(17, count)
	})
}

func Test_GlobalMigration(t *testing.T) {
	require := require.New(t)
	dialect := dbtest.Postgres
	ctx := context.Background()

	priorMigration := 96001
	currentMigration := 97005

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

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	insertRoles := `
    insert into iam_role
      (scope_id,       public_id,         name,                           description,                    version,    create_time,               update_time)
    values
      ('global', 'r_globala__test', 'Migration test global role A', 'Migration test global role A', 12,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoles)
	require.NoError(err)

	insertRoleGrantScopes := `
    insert into iam_role_grant_scope
      (role_id,          scope_id_or_special,   create_time)
    values
            ('r_globala__test', 'this',               '2025-03-01 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoleGrantScopes)
	require.NoError(err)

	tx, err := d.BeginTx(ctx, nil)
	require.NoError(err)

	// Run hook check
	_, err = hook97001.FindInvalidAssociations(ctx, tx)
	require.NoError(err)

	// Run hook repair
	_, err = hook97001.RepairInvalidAssociations(ctx, tx)
	require.NoError(err)

	err = tx.Commit()
	require.NoError(err)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	t.Run("iam_role_global migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalRoleQuery)
		require.NoError(err)
		globalRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			globalRoles = append(globalRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(globalRoles, 1)
		require.Equal([]testRole{
			{
				role_id:               "r_globala__test",
				scope_id:              "global",
				name:                  "Migration test global role A",
				description:           "Migration test global role A",
				version:               12,
				grant_this_role_scope: true,
				grant_scope:           "individual",
			},
		}, globalRoles)
	})

	t.Run("iam_role_org migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgRoleQuery)
		require.NoError(err)
		orgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			orgRoles = append(orgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(orgRoles)
	})

	t.Run("iam_role_project migration", func(t *testing.T) {
		rows, err := d.Query(selectProjectRoleQuery)
		require.NoError(err)
		projRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
			))
			projRoles = append(projRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(projRoles)
	})

	t.Run("iam_role_global_individual_org_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualOrgGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualOrgRoles)
	})

	t.Run("iam_role_global_individual_proj_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualProjectGrantScopeQuery)
		require.NoError(err)
		individualProjRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualProjRoles = append(individualProjRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualProjRoles)
	})

	t.Run("iam_role_org_individual_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgIndividualGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualOrgRoles)
	})

	t.Run("compare prior and new table counts", func(t *testing.T) {
		// the number of sub-table roles should be the same
		// as the original iam_role_grant_scope table (1)
		var count int
		row := d.QueryRowContext(ctx, selectCountSubTableRolesQuery)
		require.NoError(row.Scan(&count))
		require.Equal(1, count)
	})
}

func Test_OrgMigration(t *testing.T) {
	require := require.New(t)
	dialect := dbtest.Postgres
	ctx := context.Background()

	priorMigration := 96001
	currentMigration := 97005

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

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	// Seed the data
	insertScopes := `
    insert into iam_scope
      (parent_id,      type,      public_id,      name)
    values
      ('global',       'org',     'o_____colors', 'Colors R Us'),
      ('o_____colors', 'project', 'p____bcolors', 'Blue Color Mill');
    `
	_, err = d.ExecContext(ctx, insertScopes)
	require.NoError(err)

	insertRoles := `
    insert into iam_role
      (scope_id,       public_id,         name,                           description,                    version,    create_time,               update_time)
    values
      ('o_____colors', 'r_op_bc__art',    'Blue Color Artist',            'Creates blue colors',          4,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489');
 	`
	_, err = d.ExecContext(ctx, insertRoles)
	require.NoError(err)

	insertRoleGrantScopes := `
    insert into iam_role_grant_scope
      (role_id,          scope_id_or_special,   create_time)
    values
	  ('r_op_bc__art',    'children',           '2025-03-05 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoleGrantScopes)
	require.NoError(err)

	tx, err := d.BeginTx(ctx, nil)
	require.NoError(err)

	// Run hook check
	_, err = hook97001.FindInvalidAssociations(ctx, tx)
	require.NoError(err)

	// Run hook repair
	_, err = hook97001.RepairInvalidAssociations(ctx, tx)
	require.NoError(err)

	err = tx.Commit()
	require.NoError(err)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	t.Run("iam_role_global migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalRoleQuery)
		require.NoError(err)
		globalRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			globalRoles = append(globalRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(globalRoles)
	})

	t.Run("iam_role_org migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgRoleQuery)
		require.NoError(err)
		orgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			orgRoles = append(orgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(orgRoles, 1)
		require.Equal([]testRole{
			{
				role_id:               "r_op_bc__art",
				scope_id:              "o_____colors",
				name:                  "Blue Color Artist",
				description:           "Creates blue colors",
				version:               4,
				grant_this_role_scope: false,
				grant_scope:           "children",
			},
		}, orgRoles)
	})

	t.Run("iam_role_project migration", func(t *testing.T) {
		rows, err := d.Query(selectProjectRoleQuery)
		require.NoError(err)
		projRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
			))
			projRoles = append(projRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(projRoles)
	})

	t.Run("iam_role_global_individual_org_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualOrgGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualOrgRoles)
	})

	t.Run("iam_role_global_individual_proj_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualProjectGrantScopeQuery)
		require.NoError(err)
		individualProjRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualProjRoles = append(individualProjRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualProjRoles)
	})

	t.Run("iam_role_org_individual_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgIndividualGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualOrgRoles)
	})

	t.Run("compare prior and new table counts", func(t *testing.T) {
		// the number of sub-table roles should be the same
		// as the original iam_role_grant_scope table (1)
		var count int
		row := d.QueryRowContext(ctx, selectCountSubTableRolesQuery)
		require.NoError(row.Scan(&count))
		require.Equal(1, count)
	})
}

func Test_ProjectMigration(t *testing.T) {
	require := require.New(t)
	dialect := dbtest.Postgres
	ctx := context.Background()

	priorMigration := 96001
	currentMigration := 97005

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

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	// Seed the data
	insertScopes := `
    insert into iam_scope
      (parent_id,      type,      public_id,      name)
    values
	  ('global',       'org',     'o_ta____test', 'Org A Testing Role Grant Scope Migrations'),
      ('o_ta____test', 'project', 'p_pA____test', 'Migration test Project A');
    `
	_, err = d.ExecContext(ctx, insertScopes)
	require.NoError(err)

	insertRoles := `
    insert into iam_role
      (scope_id, public_id,      name,          description,    version, create_time,               update_time)
    values
	  ('global', 'r_globala__test', 'Migration test global role A', 'Migration test global role A', 12,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('p_pA____test', 'r_prjaa____test', 'Migration test proj A role A', 'Migration test proj A role A', 20,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoles)
	require.NoError(err)

	insertRoleGrantScopes := `
    insert into iam_role_grant_scope
      (role_id,          scope_id_or_special,   create_time)
    values
      ('r_globala__test', 'this',       '2025-03-01 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoleGrantScopes)
	require.NoError(err)

	tx, err := d.BeginTx(ctx, nil)
	require.NoError(err)

	// Run hook check
	_, err = hook97001.FindInvalidAssociations(ctx, tx)
	require.NoError(err)

	// Run hook repair
	_, err = hook97001.RepairInvalidAssociations(ctx, tx)
	require.NoError(err)

	err = tx.Commit()
	require.NoError(err)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	t.Run("iam_role_global migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalRoleQuery)
		require.NoError(err)
		globalRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			globalRoles = append(globalRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(globalRoles, 1)
		require.Equal([]testRole{
			{
				role_id:               "r_globala__test",
				scope_id:              "global",
				name:                  "Migration test global role A",
				description:           "Migration test global role A",
				version:               12,
				grant_this_role_scope: true,
				grant_scope:           "individual",
			},
		}, globalRoles)
	})

	t.Run("iam_role_org migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgRoleQuery)
		require.NoError(err)
		orgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			orgRoles = append(orgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(orgRoles)
	})

	t.Run("iam_role_project migration", func(t *testing.T) {
		rows, err := d.Query(selectProjectRoleQuery)
		require.NoError(err)
		projRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
			))
			projRoles = append(projRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(projRoles, 1)
		require.Equal([]testRole{
			{
				role_id:               "r_prjaa____test",
				scope_id:              "p_pA____test",
				name:                  "Migration test proj A role A",
				description:           "Migration test proj A role A",
				version:               20,
				grant_this_role_scope: false,
			},
		}, projRoles)
	})

	t.Run("iam_role_global_individual_org_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualOrgGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualOrgRoles)
	})

	t.Run("iam_role_global_individual_proj_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualProjectGrantScopeQuery)
		require.NoError(err)
		individualProjRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualProjRoles = append(individualProjRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualProjRoles)
	})

	t.Run("iam_role_org_individual_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgIndividualGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualOrgRoles)
	})

	t.Run("compare prior and new table counts", func(t *testing.T) {
		// the number of sub-table roles should be the same
		// as the original iam_role_grant_scope table (1)
		var count int
		row := d.QueryRowContext(ctx, selectCountSubTableRolesQuery)
		require.NoError(row.Scan(&count))
		require.Equal(1, count)
	})
}

func Test_GlobalIndividualOrgMigration(t *testing.T) {
	require := require.New(t)
	dialect := dbtest.Postgres
	ctx := context.Background()

	priorMigration := 96001
	currentMigration := 97005

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

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	// Seed the data
	insertScopes := `
    insert into iam_scope
      (parent_id,      type,      public_id,      name)
    values
      ('global',       'org',     'o_____colors', 'Colors R Us');
    `
	_, err = d.ExecContext(ctx, insertScopes)
	require.NoError(err)

	insertRoles := `
    insert into iam_role
      (scope_id, public_id,      name,          description,    version, create_time,               update_time)
    values
      ('global', 'r_go____name', 'Color Namer', 'Names colors', 8,       '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoles)
	require.NoError(err)

	insertRoleGrantScopes := `
    insert into iam_role_grant_scope
      (role_id,          scope_id_or_special,   create_time)
    values
      ('r_go____name',    'o_____colors',       '2025-03-08 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoleGrantScopes)
	require.NoError(err)

	tx, err := d.BeginTx(ctx, nil)
	require.NoError(err)

	// Run hook check
	_, err = hook97001.FindInvalidAssociations(ctx, tx)
	require.NoError(err)

	// Run hook repair
	_, err = hook97001.RepairInvalidAssociations(ctx, tx)
	require.NoError(err)

	err = tx.Commit()
	require.NoError(err)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	t.Run("iam_role_global migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalRoleQuery)
		require.NoError(err)
		globalRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			globalRoles = append(globalRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(globalRoles, 1)
		require.Equal([]testRole{
			{
				role_id:               "r_go____name",
				scope_id:              "global",
				name:                  "Color Namer",
				description:           "Names colors",
				version:               8,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
		}, globalRoles)
	})

	t.Run("iam_role_org migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgRoleQuery)
		require.NoError(err)
		orgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			orgRoles = append(orgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(orgRoles)
	})

	t.Run("iam_role_project migration", func(t *testing.T) {
		rows, err := d.Query(selectProjectRoleQuery)
		require.NoError(err)
		projRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
			))
			projRoles = append(projRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(projRoles)
	})

	t.Run("iam_role_global_individual_org_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualOrgGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(individualOrgRoles, 1)
		require.Equal([]testRole{
			{
				role_id:     "r_go____name",
				scope_id:    "o_____colors",
				grant_scope: "individual",
			},
		}, individualOrgRoles)
	})

	t.Run("iam_role_global_individual_proj_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualProjectGrantScopeQuery)
		require.NoError(err)
		individualProjRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualProjRoles = append(individualProjRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualProjRoles)
	})

	t.Run("iam_role_org_individual_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgIndividualGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualOrgRoles)
	})

	t.Run("compare prior and new table counts", func(t *testing.T) {
		// the number of sub-table roles should be the same
		// as the original iam_role_grant_scope table (1)
		var count int
		row := d.QueryRowContext(ctx, selectCountSubTableRolesQuery)
		require.NoError(row.Scan(&count))
		require.Equal(1, count)
	})
}

func Test_GlobalIndividualProjectMigration(t *testing.T) {
	require := require.New(t)
	dialect := dbtest.Postgres
	ctx := context.Background()

	priorMigration := 96001
	currentMigration := 97005

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

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	// Seed the data
	insertScopes := `
    insert into iam_scope
      (parent_id,      type,      public_id,      name)
    values
	  ('global',       'org',     'o_ta____test', 'Org A Testing Role Grant Scope Migrations'),
      ('o_ta____test', 'project', 'p_pA____test', 'Migration test Project A');
    `
	_, err = d.ExecContext(ctx, insertScopes)
	require.NoError(err)

	insertRoles := `
    insert into iam_role
      (scope_id, public_id,      name,          description,    version, create_time,               update_time)
    values
	  ('global', 'r_globala__test', 'Migration test global role A', 'Migration test global role A', 12,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('p_pA____test', 'r_prjaa____test', 'Migration test proj A role A', 'Migration test proj A role A', 20,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoles)
	require.NoError(err)

	insertRoleGrantScopes := `
    insert into iam_role_grant_scope
      (role_id,          scope_id_or_special,   create_time)
    values
      ('r_globala__test', 'p_pA____test',       '2025-03-01 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoleGrantScopes)
	require.NoError(err)

	tx, err := d.BeginTx(ctx, nil)
	require.NoError(err)

	// Run hook check
	_, err = hook97001.FindInvalidAssociations(ctx, tx)
	require.NoError(err)

	// Run hook repair
	_, err = hook97001.RepairInvalidAssociations(ctx, tx)
	require.NoError(err)

	err = tx.Commit()
	require.NoError(err)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	t.Run("iam_role_global migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalRoleQuery)
		require.NoError(err)
		globalRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			globalRoles = append(globalRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(globalRoles, 1)
		require.Equal([]testRole{
			{
				role_id:               "r_globala__test",
				scope_id:              "global",
				name:                  "Migration test global role A",
				description:           "Migration test global role A",
				version:               12,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
		}, globalRoles)
	})

	t.Run("iam_role_org migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgRoleQuery)
		require.NoError(err)
		orgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			orgRoles = append(orgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(orgRoles)
	})

	t.Run("iam_role_project migration", func(t *testing.T) {
		rows, err := d.Query(selectProjectRoleQuery)
		require.NoError(err)
		projRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
			))
			projRoles = append(projRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(projRoles, 1)
		require.Equal([]testRole{
			{
				role_id:               "r_prjaa____test",
				scope_id:              "p_pA____test",
				name:                  "Migration test proj A role A",
				description:           "Migration test proj A role A",
				version:               20,
				grant_this_role_scope: false,
			},
		}, projRoles)
	})

	t.Run("iam_role_global_individual_org_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualOrgGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualOrgRoles)
	})

	t.Run("iam_role_global_individual_proj_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualProjectGrantScopeQuery)
		require.NoError(err)
		individualProjRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualProjRoles = append(individualProjRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(individualProjRoles, 1)
		require.Equal([]testRole{
			{
				role_id:     "r_globala__test",
				scope_id:    "p_pA____test",
				grant_scope: "individual",
			},
		}, individualProjRoles)
	})

	t.Run("iam_role_org_individual_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgIndividualGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualOrgRoles)
	})

	t.Run("compare prior and new table counts", func(t *testing.T) {
		// the number of sub-table roles should be the same
		// as the original iam_role_grant_scope table (1)
		var count int
		row := d.QueryRowContext(ctx, selectCountSubTableRolesQuery)
		require.NoError(row.Scan(&count))
		require.Equal(1, count)
	})
}

func Test_OrgIndividualProjectMigration(t *testing.T) {
	require := require.New(t)
	dialect := dbtest.Postgres
	ctx := context.Background()

	priorMigration := 96001
	currentMigration := 97005

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

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	// Seed the data
	insertScopes := `
    insert into iam_scope
      (parent_id,      type,      public_id,      name)
    values
      ('global',       'org',     'o_____colors', 'Colors R Us'),
      ('o_____colors', 'project', 'p____rcolors', 'Red Color Mill');
    `
	_, err = d.ExecContext(ctx, insertScopes)
	require.NoError(err)

	insertRoles := `
    insert into iam_role
      (scope_id, public_id,      name,          description,    version, create_time,               update_time)
    values
	('p____rcolors', 'r_pp_rc__mix',    'Color Mixer', 	              'Mixes red colors',             2,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
	('o_____colors', 'r_op_rc__art',    'Red Color Artist',             'Creates red colors',           5,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoles)
	require.NoError(err)

	insertRoleGrantScopes := `
    insert into iam_role_grant_scope
      (role_id,          scope_id_or_special,   create_time)
    values
      ('r_op_rc__art',    'p____rcolors',       '2025-03-06 16:43:15.489');
    `
	_, err = d.ExecContext(ctx, insertRoleGrantScopes)
	require.NoError(err)

	tx, err := d.BeginTx(ctx, nil)
	require.NoError(err)

	// Run hook check
	_, err = hook97001.FindInvalidAssociations(ctx, tx)
	require.NoError(err)

	// Run hook repair
	_, err = hook97001.RepairInvalidAssociations(ctx, tx)
	require.NoError(err)

	err = tx.Commit()
	require.NoError(err)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(err)
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

	t.Run("iam_role_global migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalRoleQuery)
		require.NoError(err)
		globalRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			globalRoles = append(globalRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(globalRoles)
	})

	t.Run("iam_role_org migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgRoleQuery)
		require.NoError(err)
		orgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
				&r.grant_scope,
			))
			orgRoles = append(orgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(orgRoles, 1)
		require.Equal([]testRole{
			{
				role_id:               "r_op_rc__art",
				scope_id:              "o_____colors",
				name:                  "Red Color Artist",
				description:           "Creates red colors",
				version:               5,
				grant_this_role_scope: false,
				grant_scope:           "individual",
			},
		}, orgRoles)
	})

	t.Run("iam_role_project migration", func(t *testing.T) {
		rows, err := d.Query(selectProjectRoleQuery)
		require.NoError(err)
		projRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.name,
				&r.description,
				&r.version,
				&r.grant_this_role_scope,
			))
			projRoles = append(projRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(projRoles, 1)
		require.Equal([]testRole{
			{
				role_id:               "r_pp_rc__mix",
				scope_id:              "p____rcolors",
				name:                  "Color Mixer",
				description:           "Mixes red colors",
				version:               2,
				grant_this_role_scope: false,
			},
		}, projRoles)
	})

	t.Run("iam_role_global_individual_org_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualOrgGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualOrgRoles)
	})

	t.Run("iam_role_global_individual_proj_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectGlobalIndividualProjectGrantScopeQuery)
		require.NoError(err)
		individualProjRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualProjRoles = append(individualProjRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Empty(individualProjRoles)
	})

	t.Run("iam_role_org_individual_grant_scope migration", func(t *testing.T) {
		rows, err := d.Query(selectOrgIndividualGrantScopeQuery)
		require.NoError(err)
		individualOrgRoles := []testRole{}
		for rows.Next() {
			var r testRole
			require.NoError(rows.Scan(
				&r.role_id,
				&r.scope_id,
				&r.grant_scope,
			))
			individualOrgRoles = append(individualOrgRoles, r)
		}
		require.NoError(rows.Err())
		require.NoError(rows.Close())
		require.Len(individualOrgRoles, 1)
		require.Equal([]testRole{
			{
				role_id:     "r_op_rc__art",
				scope_id:    "p____rcolors",
				grant_scope: "individual",
			},
		}, individualOrgRoles)
	})

	t.Run("compare prior and new table counts", func(t *testing.T) {
		// the number of sub-table roles should be the same
		// as the original iam_role_grant_scope table (1)
		var count int
		row := d.QueryRowContext(ctx, selectCountSubTableRolesQuery)
		require.NoError(row.Scan(&count))
		require.Equal(1, count)
	})
}
