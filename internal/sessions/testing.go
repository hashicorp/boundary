package sessions

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/go-uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func TestSession(
	t *testing.T,
	conn *gorm.DB,
	userId,
	hostId,
	serverId,
	serverType,
	targetId,
	hostSetId,
	authTokenId,
	scopeId,
	address,
	port string,
	opt ...Option) *Session {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	s, err := NewSession(
		userId,
		hostId,
		serverId,
		serverType,
		targetId,
		hostSetId,
		authTokenId,
		scopeId,
		address,
		port,
		opt...,
	)
	require.NoError(err)
	id, err := newSessionId()
	require.NoError(err)
	s.PublicId = id
	err = rw.Create(context.Background(), s)
	require.NoError(err)
	return s
}

func testId(t *testing.T) string {
	t.Helper()
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	return id
}
