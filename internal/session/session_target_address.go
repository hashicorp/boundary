// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
)

const (
	defaultSessionTargetAddressTableName = "session_target_address"
)

// SessionTargetAddress contains information about a user's session with a target that has a direct network address association.
type SessionTargetAddress struct {
	// SessionId of the session
	SessionId string `json:"session_id,omitempty" gorm:"primary_key"`
	// TargetId of the session
	TargetId string `json:"target_id,omitempty" gorm:"default:null"`

	tableName string `gorm:"-"`
}

// NewSessionTargetAddress creates a new in memory session target address.
func NewSessionTargetAddress(ctx context.Context, sessionId, targetId string) (*SessionTargetAddress, error) {
	const op = "sesssion.NewSessionTargetAddress"
	if sessionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	if targetId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	sta := &SessionTargetAddress{
		SessionId: sessionId,
		TargetId:  targetId,
	}
	return sta, nil
}

// TableName returns the tablename to override the default gorm table name
func (s *SessionTargetAddress) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultSessionTargetAddressTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (s *SessionTargetAddress) SetTableName(n string) {
	s.tableName = n
}

// AllocSessionTargetAddress will allocate a SessionTargetAddress
func AllocSessionTargetAddress() *SessionTargetAddress {
	return &SessionTargetAddress{}
}

// Clone creates a clone of the SessionTargetAddress
func (s *SessionTargetAddress) Clone() any {
	clone := &SessionTargetAddress{
		SessionId: s.SessionId,
		TargetId:  s.TargetId,
	}
	return clone
}
