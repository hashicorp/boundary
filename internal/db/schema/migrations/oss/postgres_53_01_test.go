// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package oss_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrations_DeprecatedGrants(t *testing.T) {
	const (
		priorMigration   = 52001
		currentMigration = 53001
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
	rw := db.New(conn)

	// Create project
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	oId := "o_1234567890"
	pId := "p_1234567890"
	num, err := rw.Exec(ctx, `
insert into iam_scope
	(public_id, type, parent_id)
values
	(?, ?, ?)
	`, []any{oId, "org", "global"})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	num, err = rw.Exec(ctx, `
insert into iam_scope
	(public_id, type, parent_id)
values
	(?, ?, ?)
	`, []any{pId, "project", oId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	role := iam.TestRole(t, conn, pId)

	initialGrants := map[string]bool{
		"id=*;type=target;actions=read,authorize-session,add-host-sets,add-host-sets":            true,
		"id=*;type=target;actions=set-host-sets,update,delete,remove-credential-libraries":       true,
		"id=*;type=host-set;actions=read,update,set-credential-sources,set-credential-libraries": true,
		"id=*;type=target;actions=add-host-sources,remove-host-sets,add-credential-libraries":    true,
	}

	// Insert grants
	for grant := range initialGrants {
		iam.TestRoleGrant(t, conn, role.GetPublicId(), grant)
	}

	// Fetch the role
	_, _, initialRoleGrants, err := iamRepo.LookupRole(ctx, role.GetPublicId())
	require.NoError(t, err)
	require.Len(t, initialRoleGrants, len(initialGrants))

	// Initial grant check
	for _, grant := range initialRoleGrants {
		if !initialGrants[grant.RawGrant] {
			require.FailNow(t, "raw grant not found", grant.RawGrant)
		}
	}

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

	updatedGrants := make(map[string]bool, len(initialGrants))
	for grant := range initialGrants {
		updatedGrant := strings.ReplaceAll(grant, "add-host-sets", "add-host-sources")
		updatedGrant = strings.ReplaceAll(updatedGrant, "set-host-sets", "set-host-sources")
		updatedGrant = strings.ReplaceAll(updatedGrant, "remove-host-sets", "remove-host-sources")
		updatedGrant = strings.ReplaceAll(updatedGrant, "add-credential-libraries", "add-credential-sources")
		updatedGrant = strings.ReplaceAll(updatedGrant, "set-credential-libraries", "set-credential-sources")
		updatedGrant = strings.ReplaceAll(updatedGrant, "remove-credential-libraries", "remove-credential-sources")
		updatedGrants[updatedGrant] = true
	}

	// Fetch the role again
	_, _, updatedRoleGrants, err := iamRepo.LookupRole(ctx, role.GetPublicId())
	require.NoError(t, err)
	require.Len(t, updatedRoleGrants, len(updatedGrants))

	// Check updated grants
	for _, grant := range updatedRoleGrants {
		if !updatedGrants[grant.RawGrant] {
			require.FailNow(t, "raw grant not found in migrated state", grant.RawGrant)
		}
	}
}
