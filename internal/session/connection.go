package session

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultConnectionTableName = "session_connection"
)

// Session contains information about a user's session with a target
type Connection struct {
	// PublicId is used to access the connection via an API
	PublicId string `json:"public_id,omitempty" gorm:"primary_key"`
	// SessionId of the connection
	SessionId string `json:"session_id,omitempty" gorm:"default:null"`
	// ClientAddress of the connection
	ClientAddress string `json:"client_address,omitempty" gorm:"default:null"`
	// ClientPort of the connection
	ClientPort uint32 `json:"client_port,omitempty" gorm:"default:null"`
	// BackendAddress of the connection
	BackendAddress string `json:"backend_address,omitempty" gorm:"default:null"`
	// BackendPort of the connection
	BackendPort uint32 `json:"backend_port,omitempty" gorm:"default:null"`
	// BytesUp of the connection
	BytesUp uint64 `json:"bytes_up,omitempty" gorm:"default:null"`
	// BytesDown of the connection
	BytesDown uint64 `json:"bytes_down,omitempty" gorm:"default:null"`
	// ClosedReason of the conneciont
	ClosedReason string `json:"closed_reason,omitempty" gorm:"default:null"`
	// CreateTime from the RDBMS
	CreateTime *timestamp.Timestamp `json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// UpdateTime from the RDBMS
	UpdateTime *timestamp.Timestamp `json:"update_time,omitempty" gorm:"default:current_timestamp"`
	// Version of the connection
	Version uint32 `json:"version,omitempty" gorm:"default:null"`

	tableName string `gorm:"-"`
}

func (c *Connection) GetPublicId() string {
	return c.PublicId
}

var _ Cloneable = (*Connection)(nil)
var _ db.VetForWriter = (*Connection)(nil)

// New creates a new in memory session.  No options
// are currently supported.
func NewConnection(sessionID, clientAddress string, clientPort uint32, backendAddr string, backendPort uint32, opt ...Option) (*Connection, error) {
	c := Connection{
		SessionId:      sessionID,
		ClientAddress:  clientAddress,
		ClientPort:     clientPort,
		BackendAddress: backendAddr,
		BackendPort:    backendPort,
	}
	if err := c.validateNewConnection("new connection:"); err != nil {
		return nil, err
	}
	return &c, nil
}

// AllocConnection will allocate a Session
func AllocConnection() Connection {
	return Connection{}
}

// Clone creates a clone of the Session
func (c *Connection) Clone() interface{} {
	clone := &Connection{
		PublicId:       c.PublicId,
		SessionId:      c.SessionId,
		ClientAddress:  c.ClientAddress,
		ClientPort:     c.ClientPort,
		BackendAddress: c.BackendAddress,
		BackendPort:    c.BackendPort,
		BytesUp:        c.BytesUp,
		BytesDown:      c.BytesDown,
		ClosedReason:   c.ClosedReason,
		Version:        c.Version,
	}
	if c.CreateTime != nil {
		clone.CreateTime = &timestamp.Timestamp{
			Timestamp: &timestamppb.Timestamp{
				Seconds: c.CreateTime.Timestamp.Seconds,
				Nanos:   c.CreateTime.Timestamp.Nanos,
			},
		}
	}
	if c.UpdateTime != nil {
		clone.UpdateTime = &timestamp.Timestamp{
			Timestamp: &timestamppb.Timestamp{
				Seconds: c.UpdateTime.Timestamp.Seconds,
				Nanos:   c.UpdateTime.Timestamp.Nanos,
			},
		}
	}
	return clone
}

// VetForWrite implements db.VetForWrite() interface and validates the connection
// before it's written.
func (c *Connection) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	opts := db.GetOpts(opt...)
	if c.PublicId == "" {
		return fmt.Errorf("connection vet for write: missing public id: %w", db.ErrInvalidParameter)
	}
	switch opType {
	case db.CreateOp:
		if err := c.validateNewConnection("connection vet for write:"); err != nil {
			return err
		}
	case db.UpdateOp:
		switch {
		case contains(opts.WithFieldMaskPaths, "PublicId"):
			return fmt.Errorf("connection vet for write: public id is immutable: %w", db.ErrInvalidParameter)
		case contains(opts.WithFieldMaskPaths, "SessionId"):
			return fmt.Errorf("connection vet for write: session id is immutable: %w", db.ErrInvalidParameter)
		case contains(opts.WithFieldMaskPaths, "ClientAddress"):
			return fmt.Errorf("connection vet for write: client address is immutable: %w", db.ErrInvalidParameter)
		case contains(opts.WithFieldMaskPaths, "ClientPort"):
			return fmt.Errorf("connection vet for write: client port is immutable: %w", db.ErrInvalidParameter)
		case contains(opts.WithFieldMaskPaths, "BackendAddress"):
			return fmt.Errorf("connection vet for write: backend address is immutable: %w", db.ErrInvalidParameter)
		case contains(opts.WithFieldMaskPaths, "BackendPort"):
			return fmt.Errorf("connection vet for write: backend port is immutable: %w", db.ErrInvalidParameter)
		case contains(opts.WithFieldMaskPaths, "CreateTime"):
			return fmt.Errorf("connection vet for write: create time is immutable: %w", db.ErrInvalidParameter)
		case contains(opts.WithFieldMaskPaths, "UpdateTime"):
			return fmt.Errorf("connection vet for write: update time is immutable: %w", db.ErrInvalidParameter)
		case contains(opts.WithFieldMaskPaths, "ClosedReason"):
			if _, err := convertToClosedReason(c.ClosedReason); err != nil {
				return fmt.Errorf("connection vet for write: %w", db.ErrInvalidParameter)
			}
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (c *Connection) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return defaultConnectionTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (c *Connection) SetTableName(n string) {
	c.tableName = n
}

// validateNewConnection checks everything but the connection's PublicId
func (c *Connection) validateNewConnection(errorPrefix string) error {
	if c.SessionId == "" {
		return fmt.Errorf("%s missing session id: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if c.ClientAddress == "" {
		return fmt.Errorf("%s missing client address: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if c.ClientPort == 0 {
		return fmt.Errorf("%s missing client port: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if c.BackendAddress == "" {
		return fmt.Errorf("%s missing backend address: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if c.BackendPort == 0 {
		return fmt.Errorf("%s missing backend port: %w", errorPrefix, db.ErrInvalidParameter)
	}
	return nil
}
