// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package schema_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
	"github.com/hashicorp/boundary/internal/db/schema/migration"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateStore(t *testing.T) {
	dialect := dbtest.Postgres
	ctx := context.Background()

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})

	ran, err := schema.MigrateStore(ctx, schema.Dialect(dialect), u, schema.WithEditions(
		edition.Editions{
			{
				Name:          "oss",
				Dialect:       schema.Postgres,
				LatestVersion: 1,
				Migrations: migration.Migrations{
					1: migration.Migration{
						Statements: []byte(`select 1`),
						Version:    1,
						Edition:    "oss",
					},
				},
				Priority: 0,
			},
		},
	))
	assert.NoError(t, err)
	assert.True(t, ran)

	ran, err = schema.MigrateStore(ctx, schema.Dialect(dialect), u, schema.WithEditions(
		edition.Editions{
			{
				Name:          "oss",
				Dialect:       schema.Postgres,
				LatestVersion: 1,
				Migrations: migration.Migrations{
					2: migration.Migration{
						Statements: []byte(`select 1`),
						Version:    2,
						Edition:    "oss",
					},
				},
				Priority: 0,
			},
		},
	))
	assert.NoError(t, err)
	assert.False(t, ran)

	ran, err = schema.MigrateStore(ctx, schema.Dialect(dialect), u, schema.WithEditions(
		edition.Editions{
			{
				Name:          "oss",
				Dialect:       schema.Postgres,
				LatestVersion: 2,
				Migrations: migration.Migrations{
					1: migration.Migration{
						Statements: []byte(`select 1`),
						Version:    1,
						Edition:    "oss",
					},
					2: migration.Migration{
						Statements: []byte(`select 1`),
						Version:    2,
						Edition:    "oss",
					},
				},
				Priority: 0,
			},
		},
	))
	assert.NoError(t, err)
	assert.True(t, ran)
	ran, err = schema.MigrateStore(ctx, schema.Dialect(dialect), u, schema.WithEditions(
		edition.Editions{
			{
				Name:          "oss",
				Dialect:       schema.Postgres,
				LatestVersion: 2,
				Migrations: migration.Migrations{
					1: migration.Migration{
						Statements: []byte(`select 1`),
						Version:    1,
						Edition:    "oss",
					},
					2: migration.Migration{
						Statements: []byte(`select 1`),
						Version:    2,
						Edition:    "oss",
					},
				},
				Priority: 0,
			},
		},
	))
	assert.NoError(t, err)
	assert.False(t, ran)
}
