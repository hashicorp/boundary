// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
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
)

func Test_IamRoleAndGrantScopeMigration(t *testing.T) {
	require := require.New(t)
	dialect := dbtest.Postgres
	ctx := context.Background()

	priorMigration := 95001
	currentMigration := 100006

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
      ('o_____colors', 'project', 'p____gcolors', 'Green Color Mill');
	`
	_, err = d.ExecContext(ctx, insertScopes)
	require.NoError(err)

	insertRoles := `
	insert into iam_role
	  (scope_id,       public_id,      name,                   description,            version,    create_time,               update_time)
	values
      ('p____bcolors', 'r_pp_bc__mix', 'Color Mixer',          'Mixes blue colors',    1,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('p____rcolors', 'r_pp_rc__mix', 'Color Mixer', 	       'Mixes red colors',     2,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('p____gcolors', 'r_pp_gc__mix', 'Color Mixer', 	       'Mixes green colors',   3,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('o_____colors', 'r_op_bc__art', 'Blue Color Artist',    'Creates blue colors',  4,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('o_____colors', 'r_op_rc__art', 'Red Color Artist',     'Creates red colors',   5,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('o_____colors', 'r_op_gc__art', 'Green Color Artist',   'Creates green colors', 6,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
      ('o_____colors', 'r_oo_____art', 'Color Artist',		   'Creates colors',       7,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
          ('global',   'r_go____name', 'Color Namer', 		   'Names colors',         8,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
          ('global',   'r_gp____spec', 'Blue Color Inspector', 'Inspects blue colors', 9,          '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
          ('global',   'r_gg_____buy', 'Purchaser', 		   'Buys colors',          10,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489'),
          ('global',   'r_gg____shop', 'Shopper', 		       'Shops for colors',     11,         '2025-01-27 16:43:15.489', '2025-02-27 16:43:15.489');
	`
	_, err = d.ExecContext(ctx, insertRoles)
	require.NoError(err)

	insertRoleGrantScopes := `
    insert into iam_role_grant_scope
      (role_id,          scope_id_or_special,   create_time)
    values
      ('r_pp_bc__mix',   'this',                '2025-03-01 16:43:15.489'),
      ('r_pp_rc__mix',   'p____rcolors',        '2025-03-02 16:43:15.489'),
      ('r_pp_gc__mix',   'this',                '2025-03-03 16:43:15.489'),
      ('r_op_bc__art',   'p____bcolors',        '2025-03-04 16:43:15.489'),
      ('r_op_bc__art',   'children',            '2025-03-05 16:43:15.489'),
      ('r_op_rc__art',   'p____rcolors',        '2025-03-06 16:43:15.489'),
      ('r_op_gc__art',   'p____gcolors',        '2025-03-07 16:43:15.489'),
      ('r_go____name',   'o_____colors',        '2025-03-08 16:43:15.489'),
      ('r_gp____spec',   'p____bcolors',        '2025-03-09 16:43:15.489'),
      ('r_gg_____buy',   'descendants',         '2025-03-01 16:43:15.489'),
      ('r_gg____shop',   'global',              '2025-03-02 16:43:15.489'),
      ('r_gg____shop',   'children',            '2025-03-03 16:43:15.489');
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
	require.Len(globalRoles, 4)
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
	}, globalRoles)
}
