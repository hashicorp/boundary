package target

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/target/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultTcpTableName = "target_tcp"
)

type TcpTarget struct {
	*store.TcpTarget
	tableName string `gorm:"-"`
}

// NewRootKey creates a new in memory tcp target.  WithName, WithDescription and
// WithDefaultPort options are supported
func NewTcpTarget(scopeId, name string, opt ...Option) (*TcpTarget, error) {
	opts := getOpts(opt...)
	if scopeId == "" {
		return nil, fmt.Errorf("new tcp target: missing scope id: %w", db.ErrInvalidParameter)
	}
	if name == "" {
		return nil, fmt.Errorf("new tcp target: missing name: %w", db.ErrInvalidParameter)
	}
	t := &TcpTarget{
		TcpTarget: &store.TcpTarget{
			ScopeId:     scopeId,
			Name:        name,
			Description: opts.withDescription,
			DefaultPort: opts.withDefaultPort,
		},
	}
	return t, nil
}

// allocTcpTarget will allocate a tcp target
func allocTcpTarget() TcpTarget {
	return TcpTarget{
		TcpTarget: &store.TcpTarget{},
	}
}

// Clone creates a clone of the TcpTarget
func (t *TcpTarget) Clone() interface{} {
	cp := proto.Clone(t.TcpTarget)
	return &TcpTarget{
		TcpTarget: cp.(*store.TcpTarget),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the tcp target
// before it's written.
func (t *TcpTarget) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if t.PublicId == "" {
		return fmt.Errorf("tcp target vet for write: missing public id: %w", db.ErrInvalidParameter)
	}
	if opType == db.CreateOp {
		if t.ScopeId == "" {
			return fmt.Errorf("tcp target vet for write: missing scope id: %w", db.ErrInvalidParameter)
		}
		if t.Name == "" {
			return fmt.Errorf("tcp target vet for write: missing name id: %w", db.ErrInvalidParameter)
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (t *TcpTarget) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return DefaultTcpTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (t *TcpTarget) SetTableName(n string) {
	t.tableName = n
}
