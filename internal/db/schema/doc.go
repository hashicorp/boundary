// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package schema is used to apply sql migrations to modify the state of a
// database instance.  It also provides functionality to report on the state of
// a database instance and how it compares with the migration editions in the
// running binary.
//
// This package requires that the migration editions are first registered,
// prior to creating a schema.Manager. This is generally done in an init
// function of another package, i.e.:
//
//	//go:embed postgres
//	var postgres embed.FS
//
//	func init() {
//	    schema.RegisterEdition("oss", schema.Postgres, postgres, 0)
//	}
//
// Then a manager can be created and used to apply the migrations:
//
//	m := schema.NewManager(ctx, schema.Postgres, db)
//	m.ApplyMigrations()
package schema
