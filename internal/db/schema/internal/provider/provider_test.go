package provider_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
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
					Migrations: map[int][]byte{
						1: []byte(`migration one`),
						2: []byte(`migration two`),
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
					Migrations: map[int][]byte{
						1: []byte(`migration one`),
						2: []byte(`migration two`),
					},
					Priority: 0,
				},
				edition.Edition{
					Name:          "two",
					LatestVersion: 1,
					Migrations: map[int][]byte{
						1: []byte(`migration one`),
					},
					Priority: 0,
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
					Migrations: map[int][]byte{
						1: []byte(`migration one`),
						2: []byte(`migration two`),
					},
					Priority: 0,
				},
				edition.Edition{
					Name:          "two",
					LatestVersion: 1,
					Migrations: map[int][]byte{
						1: []byte(`migration one`),
					},
					Priority: 0,
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
					Migrations: map[int][]byte{
						1: []byte(`migration one`),
						2: []byte(`migration two`),
					},
					Priority: 0,
				},
				edition.Edition{
					Name:          "two",
					LatestVersion: 1,
					Migrations: map[int][]byte{
						1: []byte(`migration one`),
						2: []byte(`migration two`),
					},
					Priority: 0,
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

				assert.Equal(t, p.Version(), expected.version, tt.name)
				assert.Equal(t, p.Edition(), expected.edition, tt.name)
				assert.Equal(t, p.Statements(), expected.statements, tt.name)
			}

			assert.False(t, p.Next(), tt.name)
			assert.Equal(t, p.Version(), -1, tt.name)
			assert.Equal(t, p.Edition(), "", tt.name)
			assert.Nil(t, p.Statements(), tt.name)
		})
	}

}
