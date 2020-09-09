package session

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/session/store"
	"google.golang.org/protobuf/proto"
)

const (
	defaultStateTableName = "session_state"
)

// Status of the session's state
type Status string

const (
	StatusPending   Status = "pending"
	StatusActive    Status = "active"
	StatusCanceling Status = "canceling"
	StatusClosed    Status = "closed"
)

// String representation of the state's status
func (s Status) String() string {
	return string(s)
}

// State of the session
type State struct {
	*store.State
	tableName string `gorm:"-"`
}

var _ Cloneable = (*State)(nil)
var _ db.VetForWriter = (*State)(nil)

// NewState creates a new in memory session state.  No options
// are currently supported.
func NewState(session_id string, state Status, opt ...Option) (*State, error) {
	s := State{
		State: &store.State{
			SessionId: session_id,
			Status:    state.String(),
		},
	}

	if err := s.validate("new session:"); err != nil {
		return nil, err
	}
	return &s, nil
}

// allocState will allocate a State
func allocState() State {
	return State{
		State: &store.State{},
	}
}

// Clone creates a clone of the State
func (s *State) Clone() interface{} {
	cp := proto.Clone(s.State)
	return &State{
		State: cp.(*store.State),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the session
// before it's written.
func (s *State) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if err := s.validate("session state vet for write:"); err != nil {
		return err
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
func (s *State) validate(errorPrefix string) error {
	if s.State == nil {
		return fmt.Errorf("%s missing state: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if s.Status == "" {
		return fmt.Errorf("%s missing status: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if s.SessionId == "" {
		return fmt.Errorf("%s missing session id: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if s.StartTime != nil {
		return fmt.Errorf("%s start time is not settable: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if s.EndTime != nil {
		return fmt.Errorf("%s end time is not settable: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if s.PreviousEndTime != nil {
		return fmt.Errorf("%s previous end time is not settable: %w", errorPrefix, db.ErrInvalidParameter)
	}
	return nil
}
