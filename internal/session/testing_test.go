package session

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestSession(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s := TestDefaultSession(t, conn, wrapper, iamRepo)
	require.NotNil(s)
	assert.NotEmpty(s.PublicId)
}

func Test_TestState(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s := TestDefaultSession(t, conn, wrapper, iamRepo)
	require.NotNil(s)
	assert.NotEmpty(s.PublicId)

	state := TestState(t, conn, s.PublicId, StatusPending)
	require.NotNil(state)
}

func Test_TestConnection(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s := TestDefaultSession(t, conn, wrapper, iamRepo)
	require.NotNil(s)
	assert.NotEmpty(s.PublicId)

	c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 6500, "127.0.0.1", 22)
	require.NotNil(c)
}

func Test_TestConnectionState(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	s := TestDefaultSession(t, conn, wrapper, iamRepo)
	require.NotNil(s)
	assert.NotEmpty(s.PublicId)

	c := TestConnection(t, conn, s.PublicId, "0.0.0.0", 22, "0.0.0.0", 2222)
	require.NotNil(c)
	assert.NotEmpty(c.PublicId)

	conn.LogMode(true)
	cs := TestConnectionState(t, conn, c.PublicId, StatusClosed)
	require.NotNil(cs)

	rw := db.New(conn)
	var initialState ConnectionState
	err := rw.LookupWhere(context.Background(), &initialState, "connection_id = ? and state = ?", cs.ConnectionId, cs.Status)
	require.NoError(err)
	assert.NotEmpty(initialState.StartTime)
}
