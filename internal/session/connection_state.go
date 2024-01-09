// Copyright (c) HashiCorp, Inc.
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
	defaultConnectionStateTableName = "session_connection_state"
)

// ConnectionStatus of the connection's state
type ConnectionStatus string

const (
	StatusAuthorized  ConnectionStatus = "authorized"
	StatusConnected   ConnectionStatus = "connected"
	StatusClosed      ConnectionStatus = "closed"
	StatusUnspecified ConnectionStatus = "unspecified" // Utility state not valid in the DB
)

// String representation of the state's status
func (s ConnectionStatus) String() string {
	return string(s)
}

// ProtoVal returns the enum value corresponding to the state
func (s ConnectionStatus) ProtoVal() workerpbs.CONNECTIONSTATUS {
	switch s {
	case StatusAuthorized:
		return workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED
	case StatusConnected:
		return workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED
	case StatusClosed:
		return workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED
	}
	return workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_UNSPECIFIED
}

// ConnectionStatusFromProtoVal is the reverse of
// ConnectionStatus.ProtoVal.
func ConnectionStatusFromProtoVal(s workerpbs.CONNECTIONSTATUS) ConnectionStatus {
	switch s {
	case workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED:
		return StatusAuthorized
	case workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED:
		return StatusConnected
	case workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED:
		return StatusClosed
	}
	return StatusUnspecified
}

// ConnectionState of the state of the connection
type ConnectionState struct {
	// ConnectionId is used to access the state via an API
	ConnectionId string `json:"public_id,omitempty" gorm:"primary_key"`
	// status of the connection
	Status ConnectionStatus `protobuf:"bytes,20,opt,name=status,proto3" json:"status,omitempty" gorm:"column:state"`
	// PreviousEndTime from the RDBMS
	PreviousEndTime *timestamp.Timestamp `json:"previous_end_time,omitempty" gorm:"default:current_timestamp"`
	// StartTime from the RDBMS
	StartTime *timestamp.Timestamp `json:"start_time,omitempty" gorm:"default:current_timestamp;primary_key"`
	// EndTime from the RDBMS
	EndTime *timestamp.Timestamp `json:"end_time,omitempty" gorm:"default:current_timestamp"`

	tableName string `gorm:"-"`
}

var (
	_ Cloneable       = (*ConnectionState)(nil)
	_ db.VetForWriter = (*ConnectionState)(nil)
)

// NewConnectionState creates a new in memory connection state.  No options
// are currently supported.
func NewConnectionState(ctx context.Context, connectionId string, state ConnectionStatus, _ ...Option) (*ConnectionState, error) {
	const op = "session.NewConnectionState"
	s := ConnectionState{
		ConnectionId: connectionId,
		Status:       state,
	}
	if err := s.validate(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &s, nil
}

// allocConnectionState will allocate a connection State
func allocConnectionState() ConnectionState {
	return ConnectionState{}
}

// Clone creates a clone of the State
func (s *ConnectionState) Clone() any {
	clone := &ConnectionState{
		ConnectionId: s.ConnectionId,
		Status:       s.Status,
	}
	if s.PreviousEndTime != nil {
		clone.PreviousEndTime = &timestamp.Timestamp{
			Timestamp: &timestamppb.Timestamp{
				Seconds: s.PreviousEndTime.Timestamp.Seconds,
				Nanos:   s.PreviousEndTime.Timestamp.Nanos,
			},
		}
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
func (s *ConnectionState) VetForWrite(ctx context.Context, _ db.Reader, _ db.OpType, _ ...db.Option) error {
	const op = "session.(ConnectionState).VetForWrite"
	if err := s.validate(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (s *ConnectionState) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultConnectionStateTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (s *ConnectionState) SetTableName(n string) {
	s.tableName = n
}

// validate checks the session state
func (s *ConnectionState) validate(ctx context.Context) error {
	const op = "session.(ConnectionState).validate"
	if s.Status == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing status")
	}
	if s.ConnectionId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing connection id")
	}
	if s.StartTime != nil {
		return errors.New(ctx, errors.InvalidParameter, op, "start time is not settable")
	}
	if s.EndTime != nil {
		return errors.New(ctx, errors.InvalidParameter, op, "end time is not settable")
	}
	if s.PreviousEndTime != nil {
		return errors.New(ctx, errors.InvalidParameter, op, "previous end time is not settable")
	}
	return nil
}
