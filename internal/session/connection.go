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

// Connection contains information about session's connection to a target
type Connection struct {
	// PublicId is used to access the connection via an API
	PublicId string `json:"public_id,omitempty" gorm:"primary_key"`
	// SessionId of the connection
	SessionId string `json:"session_id,omitempty" gorm:"default:null"`
	// ClientTcpAddress of the connection
	ClientTcpAddress string `json:"client_tcp_address,omitempty" gorm:"default:null"`
	// ClientTcpPort of the connection
	ClientTcpPort uint32 `json:"client_tcp_port,omitempty" gorm:"default:null"`
	// EndpointTcpAddress of the connection
	EndpointTcpAddress string `json:"endpoint_tcp_address,omitempty" gorm:"default:null"`
	// EndpointTcpPort of the connection
	EndpointTcpPort uint32 `json:"endpoint_tcp_port,omitempty" gorm:"default:null"`
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
func NewConnection(sessionID, clientTcpAddress string, clientTcpPort uint32, endpointTcpAddr string, endpointTcpPort uint32, opt ...Option) (*Connection, error) {
	c := Connection{
		SessionId:          sessionID,
		ClientTcpAddress:   clientTcpAddress,
		ClientTcpPort:      clientTcpPort,
		EndpointTcpAddress: endpointTcpAddr,
		EndpointTcpPort:    endpointTcpPort,
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
		PublicId:           c.PublicId,
		SessionId:          c.SessionId,
		ClientTcpAddress:   c.ClientTcpAddress,
		ClientTcpPort:      c.ClientTcpPort,
		EndpointTcpAddress: c.EndpointTcpAddress,
		EndpointTcpPort:    c.EndpointTcpPort,
		BytesUp:            c.BytesUp,
		BytesDown:          c.BytesDown,
		ClosedReason:       c.ClosedReason,
		Version:            c.Version,
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
	if c.ClientTcpAddress == "" {
		return fmt.Errorf("%s missing client address: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if c.ClientTcpPort == 0 {
		return fmt.Errorf("%s missing client port: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if c.EndpointTcpAddress == "" {
		return fmt.Errorf("%s missing endpoint address: %w", errorPrefix, db.ErrInvalidParameter)
	}
	if c.EndpointTcpPort == 0 {
		return fmt.Errorf("%s missing endpoint port: %w", errorPrefix, db.ErrInvalidParameter)
	}
	return nil
}
