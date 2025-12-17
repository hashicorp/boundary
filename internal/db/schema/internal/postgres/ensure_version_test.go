// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package postgres_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnsureVersion(t *testing.T) {
	ctx := context.Background()
	p, _, _ := setup(ctx, t)

	err := p.StartRun(ctx)
	require.NoError(t, err)

	err = p.EnsureVersionTable(ctx)
	require.NoError(t, err)

	err = p.CommitRun(ctx)
	require.NoError(t, err)
}

func TestEnsureVersion_NoTxn(t *testing.T) {
	ctx := context.Background()
	p, _, _ := setup(ctx, t)
	err := p.EnsureVersionTable(ctx)
	require.Error(t, err)
}

func TestEnsureVersion_UpdateForEditionSupport(t *testing.T) {
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

	err = p.StartRun(ctx)
	require.NoError(t, err)

	err = p.EnsureVersionTable(ctx)
	require.NoError(t, err)

	err = p.CommitRun(ctx)
	require.NoError(t, err)

	var edition string
	var version int

	err = db.QueryRowContext(
		ctx,
		`select edition, version from boundary_schema_version`,
	).Scan(&edition, &version)

	require.NoError(t, err)

	assert.Equal(t, edition, "oss")
	assert.Equal(t, version, 1001)
}

func TestEnsureVersion_RenameOldSchemaTable(t *testing.T) {
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

	err = p.StartRun(ctx)
	require.NoError(t, err)

	err = p.EnsureVersionTable(ctx)
	require.NoError(t, err)

	err = p.CommitRun(ctx)
	require.NoError(t, err)

	var edition string
	var version int

	err = db.QueryRowContext(
		ctx,
		`select edition, version from boundary_schema_version`,
	).Scan(&edition, &version)

	require.NoError(t, err)

	assert.Equal(t, edition, "oss")
	assert.Equal(t, version, 1001)
}
