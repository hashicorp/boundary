// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package postgres_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurrentStatePreEdition(t *testing.T) {
	ctx := context.Background()
	p, db, _ := setup(ctx, t)

	_, err := db.ExecContext(ctx, `
	create table boundary_schema_version (
		version bigint primary key,
		dirty boolean not null
	);`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `
	insert into boundary_schema_version
	(version, dirty)
	values
	(1001, false);`)
	require.NoError(t, err)

	version, initialized, err := p.CurrentState(ctx, "oss")
	require.NoError(t, err)
	assert.Equal(t, version, 1001)
	assert.True(t, initialized)
}

func TestCurrentStateOldSchemaTable(t *testing.T) {
	ctx := context.Background()
	p, db, _ := setup(ctx, t)

	_, err := db.ExecContext(ctx, `
	create table schema_migrations (
		version bigint primary key,
		dirty boolean not null
	);`)
	require.NoError(t, err)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `
	insert into schema_migrations
	(version, dirty)
	values
	(1001, false);`)
	require.NoError(t, err)

	version, initialized, err := p.CurrentState(ctx, "oss")
	require.NoError(t, err)
	assert.Equal(t, version, 1001)
	assert.True(t, initialized)
}
