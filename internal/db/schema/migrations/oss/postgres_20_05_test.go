// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PreferredEndpointTable(t *testing.T) {
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
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": 20005}),
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
				BinarySchemaVersion:   20005,
				DatabaseSchemaVersion: 20005,
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

	// Create org scope
	orgId := "o_test___17005"
	num, err := rw.Exec(ctx, `
insert into iam_scope
	(parent_id, type, public_id, name)
values
	('global', 'org', ?, 'my-org-scope')
`, []any{orgId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create project scope
	projectId := "p_test___17005"
	num, err = rw.Exec(ctx, `
insert into iam_scope
	(parent_id, type, public_id, name)
values
	(?, 'project', ?, 'my-project-scope')`, []any{orgId, projectId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create host catalog
	hostCatalogId := "hcst_v38sxr5fY3"
	num, err = rw.Exec(ctx, `
insert into static_host_catalog
	(scope_id,  public_id,    name)
values
	(?, ?, 'my-host-catalog')`, []any{projectId, hostCatalogId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create host-set
	hostSetId := "hsst_Nt6curcj4C"
	num, err = rw.Exec(ctx, `
insert into static_host_set
	(catalog_id,    public_id,   name)
values
	(?, ?, 'my-host-set')`, []any{hostCatalogId, hostSetId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	type testCondition struct {
		condition string
		priority  uint32
	}
	insertTests := []struct {
		testName        string
		hostSetId       string
		conditions      []testCondition
		wantErrContains string
	}{
		{
			testName:  "invalid host set id",
			hostSetId: "hsst_1234567890",
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dns:abcd",
				},
				{
					priority:  2,
					condition: "cidr:1.2.3.4",
				},
			},
			wantErrContains: "host_set_fkey",
		},
		{
			testName:  "invalid condition prefix",
			hostSetId: hostSetId,
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dsn:abcd",
				},
			},
			wantErrContains: "condition_has_valid_prefix",
		},
		{
			testName:  "invalid condition length",
			hostSetId: hostSetId,
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dns:",
				},
			},
			wantErrContains: "condition_must_not_be_too_short",
		},
		{
			testName:  "invalid priority",
			hostSetId: hostSetId,
			conditions: []testCondition{
				{
					priority:  0,
					condition: "dns:abcd",
				},
			},
			wantErrContains: "priority_must_be_greater_than_zero",
		},
		{
			testName:  "duplicate priority",
			hostSetId: hostSetId,
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dns:abcd",
				},
				{
					priority:  1,
					condition: "cidr:1.2.3.4",
				},
			},
			wantErrContains: "host_set_preferred_endpoint_pkey",
		},
		{
			testName:  "invalid char 1",
			hostSetId: hostSetId,
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dns:ab|cd",
				},
				{
					priority:  1,
					condition: "cidr:1.2.3.4",
				},
			},
			wantErrContains: "condition_does_not_contain_invalid_chars",
		},
		{
			testName:  "invalid char 2",
			hostSetId: hostSetId,
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dns:abcd",
				},
				{
					priority:  1,
					condition: "cidr:1.2=.3.4",
				},
			},
			wantErrContains: "condition_does_not_contain_invalid_chars",
		},
		{
			testName:  "valid",
			hostSetId: hostSetId,
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dns:abcd",
				},
				{
					priority:  2,
					condition: "cidr:1.2.3.4",
				},
			},
		},
	}
	for _, tt := range insertTests {
		t.Run("insert: "+tt.testName, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, err := rw.Exec(ctx, "delete from host_set_preferred_endpoint where host_set_id = ?", []any{tt.hostSetId})
			require.NoError(err)

			// Add items to insert
			var items []*host.PreferredEndpoint
			for _, cond := range tt.conditions {
				ep := host.AllocPreferredEndpoint()
				ep.HostSetId = tt.hostSetId
				ep.Condition = cond.condition
				ep.Priority = cond.priority
				items = append(items, ep)
			}
			err = rw.CreateItems(ctx, items)
			if tt.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(err)
		})
	}
}
