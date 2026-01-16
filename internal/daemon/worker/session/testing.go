// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"sync"
	"testing"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/stretchr/testify/require"
)

// TestManager wraps a session manager. This wrapper allows direct manipulation of the sessions map for testing.
type TestManager struct {
	*manager
}

// NewTestManager returns a wrapped session manager that allows direct manipulation of the sessions map for testing
func NewTestManager(t *testing.T, client pbs.SessionServiceClient) *TestManager {
	sm, err := NewManager(client)
	require.NoError(t, err)
	return &TestManager{
		manager: sm,
	}
}

// StoreSession will mock an active local session with no connections in the session manager
func (m *TestManager) StoreSession(sessionId string) {
	m.manager.sessionMap.Store(sessionId, &sess{
		lock:        sync.RWMutex{},
		sessionId:   sessionId,
		connInfoMap: make(map[string]*ConnInfo),
		status:      pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
	})
}

// StoreConnection will mock a connection for the given session. The session is expected to already exist
// in the session manager.
func (m *TestManager) StoreConnection(t *testing.T, sessionId, connectionId string) {
	s, ok := m.manager.sessionMap.Load(sessionId)
	require.True(t, ok)
	localSession := s.(*sess)
	info := &ConnInfo{
		Id:     connectionId,
		Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
		BytesUp: func() int64 {
			return 0
		},
		BytesDown: func() int64 {
			return 0
		},
	}
	info.connCtxCancelFunc = func() {
		info.Status = pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED
	}
	localSession.connInfoMap[connectionId] = info
	m.manager.sessionMap.Store(sessionId, localSession)
}
