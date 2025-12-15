// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package dbtest provides a way to create a clean database for tests using
// template databases.  For it to function properly a postgres database server
// must be running with the expected templates.  This is typically done using
// the docker image provided in the docker directory of this package.
//
// To use this package in a test add something like the following in the
// beginning of the test:
//
//	c, u, _, err := dbtest.StartUsingTemplate(dbtest.Postgres)
//	require.NoError(t, err)
//	t.Cleanup(func() {
//	  require.NoError(t, c())
//	})
//	// use u to get a connection to the new database
//	dBase, err := common.SqlOpen("postgres", u)
//
// By default this uses a template that already has all of the boundary
// migrations run. If a test needs a database without any migrations, like in
// the case where the migration code needs to be tested, a different template
// can be specified. This should generally be template1:
//
//	c, u, _, err := dbtest.StartUsingTemplate(dbtest.Postgres, dbtest.WithTemplate(dbtest.Template1))
//
// See https://www.postgresql.org/docs/13/manage-ag-templatedbs.html
package dbtest
