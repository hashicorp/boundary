// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package postgres_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	ctx := context.Background()
	p, _, _ := setup(ctx, t)

	statements := bytes.NewReader([]byte(`
create table foo (
  id bigint primary key,
  bar text
);
`))

	err := p.StartRun(ctx)
	require.NoError(t, err)

	err = p.EnsureVersionTable(ctx)
	require.NoError(t, err)

	err = p.EnsureMigrationLogTable(ctx)
	require.NoError(t, err)

	err = p.Run(ctx, statements, 1001, "oss")
	require.NoError(t, err)

	err = p.CommitRun(ctx)
	require.NoError(t, err)

	v, i, err := p.CurrentState(ctx, "oss")
	require.NoError(t, err)
	assert.True(t, i)
	assert.Equal(t, v, 1001)
}

func TestRun_Rollback(t *testing.T) {
	ctx := context.Background()
	p, _, _ := setup(ctx, t)

	statements := bytes.NewReader([]byte(`
create table foo (
  id bigint primary key,
  bar text
);
`))

	err := p.StartRun(ctx)
	require.NoError(t, err)

	err = p.EnsureVersionTable(ctx)
	require.NoError(t, err)

	err = p.EnsureMigrationLogTable(ctx)
	require.NoError(t, err)

	err = p.Run(ctx, statements, 1001, "oss")
	require.NoError(t, err)

	err = p.RollbackRun(ctx)
	require.NoError(t, err)

	v, i, err := p.CurrentState(ctx, "oss")
	require.NoError(t, err)
	assert.False(t, i)
	assert.Equal(t, -1, v)
}

func TestRun_NoTxn(t *testing.T) {
	ctx := context.Background()
	p, _, _ := setup(ctx, t)

	statements := bytes.NewReader([]byte(`
create table foo (
  id bigint primary key,
  bar text
);
`))

	err := p.Run(ctx, statements, 1001, "oss")
	require.EqualError(
		t,
		err,
		fmt.Sprintf("postgres.(Postgres).Run: no pending transaction: integrity violation: error #%d", errors.MigrationIntegrity),
	)
}
