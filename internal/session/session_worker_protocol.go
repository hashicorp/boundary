// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
)

const (
	defaultSessionWorkerProtocolTableName = "session_worker_protocol"
)

// SessionWorkerProtocol contains information about a chosen protocol-aware
// worker for a session
type SessionWorkerProtocol struct {
	// SessionId of the session
	SessionId string `json:"session_id,omitempty" gorm:"primary_key"`
	// WorkerId chosen for protocol tasks
	WorkerId string `json:"worker_id,omitempty" gorm:"primary_key"`

	tableName string `gorm:"-"`
}

// NewSessionWorkerProtocol creates a new in-memory session to protocol worker
// association
func NewSessionWorkerProtocol(ctx context.Context, sessionId, workerId string) (*SessionWorkerProtocol, error) {
	const op = "session.NewSessionWorkerProtocol"
	if sessionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	if workerId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing worker id")
	}
	swp := &SessionWorkerProtocol{
		SessionId: sessionId,
		WorkerId:  workerId,
	}
	return swp, nil
}

// TableName returns the tablename to override the default gorm table name
func (s *SessionWorkerProtocol) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultSessionWorkerProtocolTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (s *SessionWorkerProtocol) SetTableName(n string) {
	s.tableName = n
}

// AllocSessionWorkerProtocol will allocate a SessionHostSetHost
func AllocSessionWorkerProtocol() *SessionWorkerProtocol {
	return &SessionWorkerProtocol{}
}

// Clone creates a clone of the SessionWorkerProtocol
func (s *SessionWorkerProtocol) Clone() any {
	clone := &SessionWorkerProtocol{
		SessionId: s.SessionId,
		WorkerId:  s.WorkerId,
	}
	return clone
}
