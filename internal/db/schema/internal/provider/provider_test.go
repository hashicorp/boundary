package provider_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
	"github.com/hashicorp/boundary/internal/db/schema/internal/migration"
	"github.com/hashicorp/boundary/internal/db/schema/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type expectedMigration struct {
	version    int
	edition    string
	statements []byte
}

type expectedMigrations []expectedMigration

func TestProvider(t *testing.T) {
	tests := []struct {
		name     string
		editions edition.Editions
		dbState  provider.DatabaseState
		expected expectedMigrations
	}{
		{
			"oneEditionNoneApplied",
			edition.Editions{
				edition.Edition{
					Name:          "one",
					LatestVersion: 2,
					Migrations: migration.Migrations{
						1: migration.Migration{
							Statements: []byte(`migration one`),
							Edition:    "one",
							Version:    1,
						},
						2: migration.Migration{
							Statements: []byte(`migration two`),
							Edition:    "one",
							Version:    2,
						},
					},
					Priority: 0,
				},
			},
			provider.DatabaseState{"one": -1},
			expectedMigrations{
				{1, "one", []byte(`migration one`)},
				{2, "one", []byte(`migration two`)},
			},
		},
		{
			"twoEditionsNoneApplied",
			edition.Editions{
				edition.Edition{
					Name:          "one",
					LatestVersion: 2,
					Migrations: migration.Migrations{
						1: migration.Migration{
							Statements: []byte(`migration one`),
							Edition:    "one",
							Version:    1,
						},
						2: migration.Migration{
							Statements: []byte(`migration two`),
							Edition:    "one",
							Version:    2,
						},
					},
					Priority: 0,
				},
				edition.Edition{
					Name:          "two",
					LatestVersion: 1,
					Migrations: migration.Migrations{
						1: migration.Migration{
							Statements: []byte(`migration one`),
							Edition:    "two",
							Version:    1,
						},
					},
					Priority: 1,
				},
			},
			provider.DatabaseState{
				"one": -1,
			},
			expectedMigrations{
				{1, "one", []byte(`migration one`)},
				{2, "one", []byte(`migration two`)},
				{1, "two", []byte(`migration one`)},
			},
		},
		{
			"twoEditionsOnePartial",
			edition.Editions{
				edition.Edition{
					Name:          "one",
					LatestVersion: 2,
					Migrations: migration.Migrations{
						1: migration.Migration{
							Statements: []byte(`migration one`),
							Edition:    "one",
							Version:    1,
						},
						2: migration.Migration{
							Statements: []byte(`migration two`),
							Edition:    "one",
							Version:    2,
						},
					},
					Priority: 0,
				},
				edition.Edition{
					Name:          "two",
					LatestVersion: 1,
					Migrations: migration.Migrations{
						1: migration.Migration{
							Statements: []byte(`migration one`),
							Edition:    "two",
							Version:    1,
						},
					},
					Priority: 1,
				},
			},
			provider.DatabaseState{
				"one": 1,
				"two": -1,
			},
			expectedMigrations{
				{2, "one", []byte(`migration two`)},
				{1, "two", []byte(`migration one`)},
			},
		},
		{
			"twoEditionsBothPartial",
			edition.Editions{
				edition.Edition{
					Name:          "one",
					LatestVersion: 2,
					Migrations: migration.Migrations{
						1: migration.Migration{
							Statements: []byte(`migration one`),
							Edition:    "one",
							Version:    1,
						},
						2: migration.Migration{
							Statements: []byte(`migration two`),
							Edition:    "one",
							Version:    2,
						},
					},
					Priority: 0,
				},
				edition.Edition{
					Name:          "two",
					LatestVersion: 1,
					Migrations: migration.Migrations{
						1: migration.Migration{
							Statements: []byte(`migration one`),
							Edition:    "two",
							Version:    1,
						},
						2: migration.Migration{
							Statements: []byte(`migration two`),
							Edition:    "two",
							Version:    2,
						},
					},
					Priority: 1,
				},
			},
			provider.DatabaseState{
				"one": 1,
				"two": 1,
			},
			expectedMigrations{
				{2, "one", []byte(`migration two`)},
				{2, "two", []byte(`migration two`)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := provider.New(tt.dbState, tt.editions)

			for _, expected := range tt.expected {
				next := p.Next()
				require.True(t, next)

				assert.Equal(t, expected.version, p.Version(), tt.name)
				assert.Equal(t, expected.edition, p.Edition(), tt.name)
				assert.Equal(t, expected.statements, p.Statements(), tt.name)
			}

			assert.False(t, p.Next(), tt.name)
			assert.Equal(t, -1, p.Version(), tt.name)
			assert.Equal(t, "", p.Edition(), tt.name)
			assert.Nil(t, p.Statements(), tt.name)
		})
	}
}
