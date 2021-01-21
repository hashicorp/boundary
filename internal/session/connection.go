package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
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

var (
	_ Cloneable       = (*Connection)(nil)
	_ db.VetForWriter = (*Connection)(nil)
)

// New creates a new in memory session.  No options
// are currently supported.
func NewConnection(sessionID, clientTcpAddress string, clientTcpPort uint32, endpointTcpAddr string, endpointTcpPort uint32, _ ...Option) (*Connection, error) {
	const op = "session.NewConnection"
	c := Connection{
		SessionId:          sessionID,
		ClientTcpAddress:   clientTcpAddress,
		ClientTcpPort:      clientTcpPort,
		EndpointTcpAddress: endpointTcpAddr,
		EndpointTcpPort:    endpointTcpPort,
	}
	if err := c.validateNewConnection(); err != nil {
		return nil, errors.Wrap(err, op)
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
func (c *Connection) VetForWrite(_ context.Context, _ db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "session.(Connection).VetForWrite"
	opts := db.GetOpts(opt...)
	if c.PublicId == "" {
		return errors.New(errors.InvalidParameter, op, "missing public id")
	}
	switch opType {
	case db.CreateOp:
		if err := c.validateNewConnection(); err != nil {
			return errors.Wrap(err, op)
		}
	case db.UpdateOp:
		switch {
		case contains(opts.WithFieldMaskPaths, "PublicId"):
			return errors.New(errors.InvalidParameter, op, "public id is immutable")
		case contains(opts.WithFieldMaskPaths, "SessionId"):
			return errors.New(errors.InvalidParameter, op, "session id is immutable")
		case contains(opts.WithFieldMaskPaths, "CreateTime"):
			return errors.New(errors.InvalidParameter, op, "create time is immutable")
		case contains(opts.WithFieldMaskPaths, "UpdateTime"):
			return errors.New(errors.InvalidParameter, op, "update time is immutable")
		case contains(opts.WithFieldMaskPaths, "ClosedReason"):
			if _, err := convertToClosedReason(c.ClosedReason); err != nil {
				return errors.Wrap(err, op)
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
func (c *Connection) validateNewConnection() error {
	const op = "session.(Connection).validateNewConnection"
	if c.SessionId == "" {
		return errors.New(errors.InvalidParameter, op, "missing session id")
	}
	if c.ClientTcpAddress == "" {
		return errors.New(errors.InvalidParameter, op, "missing client address")
	}
	if c.ClientTcpPort == 0 {
		return errors.New(errors.InvalidParameter, op, "missing client port")
	}
	if c.EndpointTcpAddress == "" {
		return errors.New(errors.InvalidParameter, op, "missing endpoint address")
	}
	if c.EndpointTcpPort == 0 {
		return errors.New(errors.InvalidParameter, op, "missing endpoint port")
	}
	return nil
}
