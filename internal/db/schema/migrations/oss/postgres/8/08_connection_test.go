// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package migration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/require"
)

func TestMigration(t *testing.T) {
	require := require.New(t)
	const (
		createTables = `
		create table session_testing (
			public_id text primary key,
			server_id text
		);
		create table session_connection_testing (
			public_id text primary key,
			session_id text,
			server_id text
		);
		
	`
		insertSession           = `insert into session_testing values ($1, $2)`
		insertSessionConnection = `insert into session_connection_testing values ($1, $2)`

		update = `
		update session_connection_testing sc
		set
		  server_id = s.server_id
		from
		  session_testing s
		where
		  sc.session_id = s.public_id;
		`
		selectQuery = `select session_id, server_id from session_connection_testing order by session_id`
	)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres", db.WithTemplate("template1"))
	db, err := conn.SqlDB(ctx)
	require.NoError(err)
	_, err = db.Exec(createTables)
	require.NoError(err)

	tests := []struct {
		sessId       string
		sessServerId string
		connId       string
	}{
		{
			"sess1",
			"server1",
			"conn1",
		},
		{
			"sess2",
			"server1",
			"conn2",
		},
		{
			"sess3",
			"server2",
			"conn3",
		},
		{
			"sess4",
			"server2",
			"conn4",
		},
	}
	for _, tt := range tests {
		_, err = db.Query(insertSession, tt.sessId, tt.sessServerId)
		require.NoError(err)
		_, err := db.Query(insertSessionConnection, tt.connId, tt.sessId)
		require.NoError(err)
	}

	// At this point server ID should be empty in connections table
	rows, err := db.Query(selectQuery)
	require.NoError(err)
	var sessVal string
	var serverVal sql.NullString
	for rows.Next() {
		require.NoError(rows.Scan(&sessVal, &serverVal))
		require.False(serverVal.Valid)
	}
	require.NoError(rows.Err())

	_, err = db.Query(update)
	require.NoError(err)

	// Now it should match the server
	rows, err = db.Query(selectQuery)
	require.NoError(err)
	var count int
	for rows.Next() {
		require.NoError(rows.Scan(&sessVal, &serverVal))
		require.True(serverVal.Valid)
		require.Equal(tests[count].sessServerId, serverVal.String)
		count++
	}
	require.NoError(rows.Err())
}
