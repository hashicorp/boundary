// Package provider provides an iterator for iterating over all of the
// migration statements that need to be applied. It will provide the statements
// in the correct order based on the Edition priority and migration version.
package provider

import (
	"sort"

	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
)

const nilVersion = -1

type migration struct {
	version    int
	edition    string
	statements []byte
}

// Provider provides the migrations to the schema.Manager in the correct order.
type Provider struct {
	pos        int
	migrations []migration
}

// DatabaseState is a map of edition names to versions.
type DatabaseState map[string]int

// New creates a Provider. The given DatabaseState is compared against the editions
// to determine which migrations need to be applied and the migrations are then ordered
// based on the Edition priority and by the migration version.
func New(dbState DatabaseState, editions edition.Editions) *Provider {
	m := &Provider{
		pos: -1,
	}

	// ensure editions in priority order
	editions.Sort()

	allMigrations := make([]migration, 0)

	for _, e := range editions {
		dbVer, ok := dbState[e.Name]
		if !ok {
			dbVer = nilVersion
		}

		migrations := make([]migration, 0, len(e.Migrations))
		for ver, statements := range e.Migrations {
			if ver > dbVer {
				migrations = append(migrations, migration{
					version:    ver,
					edition:    e.Name,
					statements: statements,
				})
			}
		}

		sort.SliceStable(migrations, func(i, j int) bool {
			return migrations[i].version < migrations[j].version
		})

		allMigrations = append(allMigrations, migrations...)
	}

	m.migrations = allMigrations

	return m
}

// Next proceeds to the next migration. It returns true on success or false
// if there are no more migrations.
func (p *Provider) Next() bool {
	p.pos++
	return len(p.migrations) > p.pos
}

// Version returns the version for the current migration.
func (p *Provider) Version() int {
	if p.pos < 0 || p.pos >= len(p.migrations) {
		return -1
	}
	return p.migrations[p.pos].version
}

// Edition returns the edition name for the current migration.
func (p *Provider) Edition() string {
	if p.pos < 0 || p.pos >= len(p.migrations) {
		return ""
	}
	return p.migrations[p.pos].edition
}

// Statements returns the sql statements name for the current migration.
func (p *Provider) Statements() []byte {
	if p.pos < 0 || p.pos >= len(p.migrations) {
		return nil
	}
	return p.migrations[p.pos].statements
}
