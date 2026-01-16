// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package schema_test

import (
	"context"
	"database/sql"
	"embed"
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
	"github.com/hashicorp/boundary/internal/db/schema/migration"
	"github.com/stretchr/testify/assert"
)

type testEdition struct {
	name     string
	dialect  schema.Dialect
	fs       embed.FS
	priority int
}

var (
	//go:embed testdata/one
	one embed.FS

	//go:embed testdata/two
	two embed.FS

	//go:embed testdata/three
	three embed.FS

	//go:embed testdata/hooks/initial
	hooksInitial embed.FS

	//go:embed testdata/hooks/updated
	hooksUpdated embed.FS
)

func TestRegisterEditionPanics(t *testing.T) {
	tests := []struct {
		name     string
		editions []testEdition
		opts     []edition.Option
	}{
		{
			"unsupportedDialect",
			[]testEdition{
				{
					"one",
					schema.Dialect("mongodb"),
					one,
					0,
				},
			},
			nil,
		},
		{
			"duplicateName",
			[]testEdition{
				{
					"one",
					schema.Postgres,
					one,
					0,
				},
				{
					"one",
					schema.Postgres,
					one,
					1,
				},
			},
			nil,
		},
		{
			"duplicatePriority",
			[]testEdition{
				{
					"one",
					schema.Postgres,
					one,
					0,
				},
				{
					"two",
					schema.Postgres,
					two,
					0,
				},
			},
			nil,
		},
		{
			"hookWithNoMigration",
			[]testEdition{
				{
					"one",
					schema.Postgres,
					one,
					0,
				},
			},
			[]edition.Option{
				edition.WithPreHooks(
					map[int]*migration.Hook{
						1099: {
							CheckFunc: func(ctx context.Context, tx *sql.Tx) (migration.Problems, error) {
								return nil, nil
							},
						},
					},
				),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Panics(t, func() {
				for _, e := range tt.editions {
					schema.RegisterEdition(e.name, e.dialect, e.fs, e.priority, tt.opts...)
				}
			}, tt.name)
		})
	}
}

func TestRegisterEdition(t *testing.T) {
	tests := []struct {
		name     string
		editions []testEdition
	}{
		{
			"singleEdition",
			[]testEdition{
				{
					"one",
					schema.Postgres,
					one,
					0,
				},
			},
		},
		{
			"twoEditions",
			[]testEdition{
				{
					"one",
					schema.Postgres,
					one,
					0,
				},
				{
					"two",
					schema.Postgres,
					one,
					1,
				},
			},
		},
		{
			"threeEditions",
			[]testEdition{
				{
					"one",
					schema.Postgres,
					one,
					0,
				},
				{
					"two",
					schema.Postgres,
					one,
					1,
				},
				{
					"three",
					schema.Postgres,
					one,
					3,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				schema.TestClearEditions(t)
				for _, e := range tt.editions {
					schema.RegisterEdition(e.name, e.dialect, e.fs, e.priority)
				}
			}, tt.name)
		})
	}
	schema.TestClearEditions(t)
}
