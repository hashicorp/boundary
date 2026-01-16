// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/types/known/timestamppb"

	workerpbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

const (
	defaultStateTableName = "session_state"
)

// Status of the session's state
type Status string

const (
	StatusPending    Status = "pending"
	StatusActive     Status = "active"
	StatusCanceling  Status = "canceling"
	StatusTerminated Status = "terminated"
)

// String representation of the state's status
func (s Status) String() string {
	return string(s)
}

// ProtoVal returns the enum value corresponding to the state
func (s Status) ProtoVal() workerpbs.SESSIONSTATUS {
	switch s {
	case StatusPending:
		return workerpbs.SESSIONSTATUS_SESSIONSTATUS_PENDING
	case StatusActive:
		return workerpbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE
	case StatusCanceling:
		return workerpbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING
	case StatusTerminated:
		return workerpbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED
	}
	return workerpbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED
}

// State of the session
type State struct {
	// SessionId references the session public id
	SessionId string `json:"session_id,omitempty" gorm:"primary_key"`
	// status of the session
	Status Status `json:"status,omitempty" gorm:"column:state"`
	// StartTime from the RDBMS
	StartTime *timestamp.Timestamp `json:"start_time,omitempty" gorm:"default:current_timestamp;primary_key"`
	// EndTime from the RDBMS
	EndTime *timestamp.Timestamp `json:"end_time,omitempty" gorm:"default:current_timestamp"`

	tableName string `gorm:"-"`
}

var (
	_ Cloneable       = (*State)(nil)
	_ db.VetForWriter = (*State)(nil)
)

// NewState creates a new in memory session state.  No options
// are currently supported.
func NewState(ctx context.Context, session_id string, state Status, _ ...Option) (*State, error) {
	const op = "session.NewState"
	s := State{
		SessionId: session_id,
		Status:    state,
	}

	if err := s.validate(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &s, nil
}

// allocState will allocate a State
func allocState() State {
	return State{}
}

// Clone creates a clone of the State
func (s *State) Clone() any {
	clone := &State{
		SessionId: s.SessionId,
		Status:    s.Status,
	}
	if s.StartTime != nil {
		clone.StartTime = &timestamp.Timestamp{
			Timestamp: &timestamppb.Timestamp{
				Seconds: s.StartTime.Timestamp.Seconds,
				Nanos:   s.StartTime.Timestamp.Nanos,
			},
		}
	}
	if s.EndTime != nil {
		clone.EndTime = &timestamp.Timestamp{
			Timestamp: &timestamppb.Timestamp{
				Seconds: s.EndTime.Timestamp.Seconds,
				Nanos:   s.EndTime.Timestamp.Nanos,
			},
		}
	}
	return clone
}

// VetForWrite implements db.VetForWrite() interface and validates the state
// before it's written.
func (s *State) VetForWrite(ctx context.Context, _ db.Reader, _ db.OpType, _ ...db.Option) error {
	const op = "session.(State).VetForWrite"
	if err := s.validate(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (s *State) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultStateTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (s *State) SetTableName(n string) {
	s.tableName = n
}

// validate checks the session state
func (s *State) validate(ctx context.Context) error {
	const op = "session.(State).validate"
	if s.Status == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing status")
	}
	if s.SessionId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	if s.StartTime != nil {
		return errors.New(ctx, errors.InvalidParameter, op, "start time is not settable")
	}
	if s.EndTime != nil {
		return errors.New(ctx, errors.InvalidParameter, op, "end time is not settable")
	}
	return nil
}
