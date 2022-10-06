package oss_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrations_BytesUpDownTrigger(t *testing.T) {
	const targetMigration = 56001

	t.Parallel()
	dialect := dbtest.Postgres

	cleanFn, url, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cleanFn()) })

	sqlDb, err := common.SqlOpen(dialect, url)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDb.Close()) })

	ctx := context.Background()
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), sqlDb, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": targetMigration}),
	))
	require.NoError(t, err)

	_, err = m.ApplyMigrations(ctx)
	require.NoError(t, err)

	state, err := m.CurrentState(ctx)
	require.NoError(t, err)
	require.Equal(t, &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   targetMigration,
				DatabaseSchemaVersion: targetMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}, state)

	conn, err := db.Open(ctx, db.Postgres, url)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close(ctx)) })

	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, proj := iam.TestScopes(t, iamRepo)
	kms := kms.TestKms(t, conn, wrapper)

	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())

	rw := db.New(conn)

	// Create host catalog
	hostCatalogId := "hcst_iope61jK"
	num, err := rw.Exec(ctx, `
		insert into static_host_catalog
			(project_id, public_id, name)
		values
			(?, ?, ?)
		`, []interface{}{proj.GetPublicId(), hostCatalogId, "my-host-catalog"})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create host set
	hostSetId := "hsst_ASgK34hUa"
	num, err = rw.Exec(ctx, `
		insert into static_host_set
			(public_id, catalog_id)
		values
			(?, ?)
		`, []interface{}{hostSetId, hostCatalogId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create host
	hostId := "hst_sHJKE38uL"
	num, err = rw.Exec(ctx, `
		insert into static_host
			(public_id, catalog_id, address)
		values
			(?, ?, ?)
		`, []interface{}{hostId, hostCatalogId, "0.0.0.0"})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Associate host to host set
	num, err = rw.Exec(ctx, `
		insert into static_host_set_member
			(host_id, set_id)
		values
			(?, ?)
		`, []interface{}{hostId, hostSetId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create a target
	targetId := "ttcp_HJKg34gLK"
	num, err = rw.Exec(ctx, `
		insert into target_tcp
			(public_id, project_id, name, session_max_seconds, session_connection_limit)
		values
			(?, ?, ?, ?, ?);
		`, []interface{}{targetId, proj.GetPublicId(), "my-credential-sources", 28800, -1})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Associate host set to target
	num, err = rw.Exec(ctx, `
		insert into target_host_set
			(target_id, host_set_id)
		values
			(?, ?)
			`, []interface{}{targetId, hostSetId})
	require.NoError(t, err)
	assert.Equal(t, 1, num)

	// Create session
	sessionId := "s_HSDFK5ujeL"
	num, err = rw.Exec(ctx, `
		insert into session
			(public_id, user_id, host_id, target_id, host_set_id, auth_token_id, project_id, certificate, endpoint)
		values
			(?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, []interface{}{sessionId, at.GetIamUserId(), hostId, targetId, hostSetId, at.GetPublicId(), proj.GetPublicId(), []byte{1, 2, 3, 4}, "endpoint"})
	require.NoError(t, err)
	require.Equal(t, 1, num)

	// Create session connection
	sessionConnId := "sc_b34Wgjkw"
	num, err = rw.Exec(ctx, `
		insert into session_connection
			(public_id, session_id, bytes_up, bytes_down)
		values
			(?, ?, ?, ?)
	`, []interface{}{sessionConnId, sessionId, 1000, 2000})
	require.NoError(t, err)
	require.Equal(t, 1, num)

	// Assert bytes up and down were inserted correctly
	rows, err := rw.Query(ctx,
		"select bytes_up, bytes_down from session_connection where public_id = ?",
		[]interface{}{sessionConnId})
	require.NoError(t, err)
	require.True(t, rows.Next())

	var bytesUp, bytesDown uint64
	require.NoError(t, rows.Scan(&bytesUp, &bytesDown))
	require.EqualValues(t, 1000, bytesUp)
	require.EqualValues(t, 2000, bytesDown)

	// Modify bytes up and down, and assert they were updated.
	num, err = rw.Exec(ctx, `
		update session_connection set (bytes_up, bytes_down) = (?, ?)
		where public_id = ?`,
		[]interface{}{3000, 4000, sessionConnId})
	require.NoError(t, err)
	require.Equal(t, 1, num)

	rows, err = rw.Query(ctx,
		"select bytes_up, bytes_down from session_connection where public_id = ?",
		[]interface{}{sessionConnId})
	require.NoError(t, err)
	require.True(t, rows.Next())

	require.NoError(t, rows.Scan(&bytesUp, &bytesDown))
	require.EqualValues(t, 3000, bytesUp)
	require.EqualValues(t, 4000, bytesDown)

	// "Close" the connection and update bytes up and down, simulating the
	// connection closure logic.
	connClosureBytesUp := 5000
	connClosureBytesDown := 6000
	num, err = rw.Exec(ctx, `
	update session_connection set (closed_reason, bytes_up, bytes_down) = (?, ?, ?)
		where public_id = ?`, []interface{}{"unknown", connClosureBytesUp, connClosureBytesDown, sessionConnId})
	require.NoError(t, err)
	require.Equal(t, 1, num)

	// The connection is now "closed". Attempt to modify various fields in the
	// row (including bytes up and down).
	clientTcpPort := 1000
	endpointTcpPort := 2000
	num, err = rw.Exec(ctx, `
		update session_connection set (client_tcp_port, endpoint_tcp_port, bytes_up, bytes_down) = (?, ?, ?, ?)
		where public_id = ?`,
		[]interface{}{clientTcpPort, endpointTcpPort, 7000, 8000, sessionConnId})
	require.NoError(t, err)  // Updating bytes up and down on a closed connection should not trigger a database error.
	require.Equal(t, 1, num) // There's still an update anyways.

	// Assert bytes_up and bytes_down don't change, but the rest does.
	rows, err = rw.Query(ctx,
		`select
		  client_tcp_port,
		  endpoint_tcp_port,
		  bytes_up,
		  bytes_down
		from session_connection
		where public_id = ?`,
		[]interface{}{sessionConnId})
	require.NoError(t, err)
	require.True(t, rows.Next())

	var dbClientTcpPort, dbEndpointTcpPort int
	require.NoError(t, rows.Scan(&dbClientTcpPort, &dbEndpointTcpPort, &bytesUp, &bytesDown))
	require.EqualValues(t, clientTcpPort, dbClientTcpPort)
	require.EqualValues(t, endpointTcpPort, dbEndpointTcpPort)
	require.EqualValues(t, connClosureBytesUp, bytesUp)
	require.EqualValues(t, connClosureBytesDown, bytesDown)
}
