// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// import for init side-effects to include migrations
	_ "github.com/hashicorp/boundary/internal/db/schema/migrations/oss"
)

func TestApplyMigrations(t *testing.T) {
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	ctx := context.Background()
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d)
	require.NoError(t, err)
	_, err = m.ApplyMigrations(ctx)
	assert.NoError(t, err)
}

func TestApplyMigrations_NotFromFresh(t *testing.T) {
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	// Initialize the DB with only a portion of the current sql scripts.
	ctx := context.Background()
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": 1}),
	))
	require.NoError(t, err)
	_, err = m.ApplyMigrations(ctx)
	assert.NoError(t, err)

	state, err := m.CurrentState(ctx)
	require.NoError(t, err)
	want := &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   1,
				DatabaseSchemaVersion: 1,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	assert.Equal(t, want, state)

	newM, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": 3}),
	))
	require.NoError(t, err)
	_, err = newM.ApplyMigrations(ctx)
	assert.NoError(t, err)
	state, err = newM.CurrentState(ctx)
	require.NoError(t, err)
	want = &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   3,
				DatabaseSchemaVersion: 3,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	assert.Equal(t, want, state)
}
