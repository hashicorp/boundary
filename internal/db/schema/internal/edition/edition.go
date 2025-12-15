// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package edition provides internal structs for the schema package for
// defining and organizing database migration editions.
package edition

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/internal/db/schema/migration"
)

// Dialect is a specific SQL language variant. This generally is the same as
// a specific SQL server implementation.
type Dialect string

func (d Dialect) String() string {
	return string(d)
}

// Edition is a collection of sql statements along with a version number.
// It is used to apply changes to the database instance.
type Edition struct {
	// The identifier of an edition. The Name and Dialect pair should be unique.
	Name string
	// The specific SQL language variant that the Migrtions are for. The Name
	// and Dialect pair should be unique.
	Dialect Dialect

	// The latest version of the schema for this edition that this binary supports.
	LatestVersion int

	// The set of migrations that should be applied to a database to reach the latest version.
	// This is a map of schema versions to sql.
	Migrations migration.Migrations

	// Priority is used to determine the order that multiple Editions should be applied.
	Priority int
}

// Editions is a collection of Edition
type Editions []Edition

// Sort orders the Editions by priority.
func (e Editions) Sort() {
	sort.SliceStable(e, func(i, j int) bool {
		return e[i].Priority < e[j].Priority
	})
}

// New creates an Edition with the provided parameters. The embed.FS m will be
// walked to extract the sql statements. The priority is used to determine
// when this Edition's migrations are applied relative to other Editions. A
// lower number indicates a higher priority. New will panic if the structure
// of the embed.FS is not correct. The files must be structured as follows:
//
//	<majorVersion>/
//	    <minorVersion>_<description>.up.sql
//
// Where majorVersion and minorVersion are integers. There can be any number of
// leading directories prior to the major versions. For example a directory
// structure like the following is correct:
//
//	migrations/oss/postgres/
//	 0/
//	   01_initial.up.sql
//	 1/
//	   01_add_columns.up.sql
//	   02_rename_table.up.sql
//	 2/
//	   01_add_new_table.up.sql
//	   02_refactor_views.up.sql
func New(name string, dialect Dialect, m embed.FS, priority int, opt ...Option) (Edition, error) {
	const beginStmt = "begin;"
	const commitStmt = "commit;"

	var largestSchemaVersion int
	migrations := make(migration.Migrations)

	opts := getOpts(opt...)
	prehook := opts.withPreHooks

	err := fs.WalkDir(m, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("unable to process migration files: %s", err)
		}

		if d.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".up.sql") {
			return nil
		}

		dir, file := filepath.Split(path)
		verMajorDir := filepath.Base(dir)

		verMajor, err := strconv.Atoi(verMajorDir)
		if err != nil {
			return fmt.Errorf("migration file does not have valid major version directory: %s", path)
		}

		verMinor, err := strconv.Atoi(strings.SplitN(file, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration file does not have valid minor version prefix: %s", path)
		}

		fullV := (verMajor * 1000) + verMinor
		if fullV > largestSchemaVersion {
			largestSchemaVersion = fullV
		}

		cbts, err := m.ReadFile(path)
		if err != nil {
			return fmt.Errorf("unable to read migration file: %s", path)
		}

		contents := strings.TrimSpace(string(cbts))
		if beginIdx := strings.Index(contents, beginStmt); beginIdx != -1 {
			contents = contents[beginIdx+len(beginStmt):]
		}
		if strings.ToLower(contents[len(contents)-len(commitStmt):]) == commitStmt {
			contents = contents[:len(contents)-len(commitStmt)]
		}
		contents = strings.TrimSpace(contents)

		if _, exists := migrations[fullV]; exists {
			return fmt.Errorf("migration file for version %d already exists", fullV)
		}
		migrations[fullV] = migration.Migration{
			Edition:    name,
			Statements: []byte(contents),
			Version:    fullV,
			PreHook:    prehook[fullV],
		}

		return nil
	})
	if err != nil {
		return Edition{}, err
	}

	for k := range prehook {
		_, ok := migrations[k]
		if !ok {
			return Edition{}, fmt.Errorf("prehook for version %d does not correspond with a migration", k)
		}
	}

	return Edition{
		Name:          name,
		Dialect:       dialect,
		LatestVersion: largestSchemaVersion,
		Migrations:    migrations,
		Priority:      priority,
	}, nil
}
