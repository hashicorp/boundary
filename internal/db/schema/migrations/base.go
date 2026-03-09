// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package migrations contains the base sql statements needed to bootstrap the
// migration process. These statements setup the tables necessary for tracking
// the state of migrations.
package migrations

import (
	"embed"
	"fmt"
	"strings"
)

// postgres contains the sql for creating the base tables used to manage
// migrations.
//
//go:embed base/postgres
var postgres embed.FS

// Base contains the sql migrtaions needed to create the initial based tables used
// to manage other migrations.
// Unlike the other migrations these create statements represent the "current" state of the tables
// and are only used on a fresh install.
type base struct {
	CreateSchemaVersion string
	CreateLogMigration  string
}

var baseByDialect map[string]base

func stripBeginCommit(c []byte) string {
	contents := strings.TrimSpace(string(c))
	if strings.ToLower(contents[:len("begin;")]) == "begin;" {
		contents = contents[len("begin;"):]
	}
	if strings.ToLower(contents[len(contents)-len("commit;"):]) == "commit;" {
		contents = contents[:len(contents)-len("commit;")]
	}
	contents = strings.TrimSpace(contents)
	return contents
}

func newBase(root string, m embed.FS) base {
	schemaVersion, err := m.ReadFile(fmt.Sprintf("%s/%s", root, "01_boundary_schema_version.up.sql"))
	if err != nil {
		panic("missing base migration file 01_boundary_schema_version.up.sql")
	}

	logMigration, err := m.ReadFile(fmt.Sprintf("%s/%s", root, "02_log_migration.up.sql"))
	if err != nil {
		panic("missing base migration file 02_log_migration.up.sql")
	}

	return base{
		CreateSchemaVersion: stripBeginCommit(schemaVersion),
		CreateLogMigration:  stripBeginCommit(logMigration),
	}
}

func init() {
	baseByDialect = map[string]base{
		"postgres": newBase("base/postgres", postgres),
	}
}

// Base returns the base create statements for the given dialect.
func Base(dialect string) base {
	return baseByDialect[dialect]
}
