// Package tcp provides a Target subtype for a TCP Target.
// Importing this package will register it with the target package and
// allow the target.Repository to support tcp.Targets.
package tcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp/store"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	"google.golang.org/protobuf/proto"
)

const (
	defaultTableName = "target_tcp"
	Subtype          = subtypes.Subtype("tcp")
)

// Target is a resources that represets a networked service
// that can be accessed via TCP. It is a subtype of target.Target.
type Target struct {
	*store.Target
	tableName string `gorm:"-"`
}

// Ensure Target implements interfaces
var (
	_ target.Target           = (*Target)(nil)
	_ db.VetForWriter         = (*Target)(nil)
	_ oplog.ReplayableMessage = (*Target)(nil)
)

// New creates a new in memory tcp target.  WithName, WithDescription and
// WithDefaultPort options are supported
func New(scopeId string, opt ...target.Option) (*Target, error) {
	const op = "tcp.NewTarget"
	opts := target.GetOpts(opt...)
	if scopeId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing scope id")
	}
	t := &Target{
		Target: &store.Target{
			ScopeId:                scopeId,
			Name:                   opts.WithName,
			Description:            opts.WithDescription,
			DefaultPort:            opts.WithDefaultPort,
			SessionConnectionLimit: opts.WithSessionConnectionLimit,
			SessionMaxSeconds:      opts.WithSessionMaxSeconds,
			WorkerFilter:           opts.WithWorkerFilter,
		},
	}
	return t, nil
}

// allocTarget will allocate a tcp target
func allocTarget() target.Target {
	return &Target{
		Target: &store.Target{},
	}
}

// Clone creates a clone of the Target
func (t *Target) Clone() target.Target {
	cp := proto.Clone(t.Target)
	return &Target{
		Target: cp.(*store.Target),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the tcp target
// before it's written.
func (t *Target) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "tcp.(Target).VetForWrite"
	if t.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if opType == db.CreateOp {
		if t.ScopeId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
		}
		if t.Name == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing name")
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (t *Target) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return defaultTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (t *Target) SetTableName(n string) {
	t.tableName = n
}

// Oplog provides the oplog.Metadata for recording operations taken on a Target.
func (t *Target) Oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{t.PublicId},
		"resource-type":      []string{"tcp target"},
		"op-type":            []string{op.String()},
		"scope-id":           []string{t.ScopeId},
	}
	return metadata
}

func (t *Target) GetType() subtypes.Subtype {
	return Subtype
}

func (t *Target) SetPublicId(ctx context.Context, publicId string) error {
	const op = "tcp.(Target).SetPublicId"
	if !strings.HasPrefix(publicId, TargetPrefix+"_") {
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("passed-in public ID %q has wrong prefix, should be %q", publicId, TargetPrefix))
	}

	t.PublicId = publicId
	return nil
}

func (t *Target) SetScopeId(scopeId string) {
	t.ScopeId = scopeId
}

func (t *Target) SetName(name string) {
	t.Name = name
}

func (t *Target) SetDescription(description string) {
	t.Description = description
}

func (t *Target) SetVersion(v uint32) {
	t.Version = v
}

func (t *Target) SetDefaultPort(port uint32) {
	t.DefaultPort = port
}

func (t *Target) SetCreateTime(ts *timestamp.Timestamp) {
	t.CreateTime = ts
}

func (t *Target) SetUpdateTime(ts *timestamp.Timestamp) {
	t.UpdateTime = ts
}

func (t *Target) SetSessionMaxSeconds(s uint32) {
	t.SessionMaxSeconds = s
}

func (t *Target) SetSessionConnectionLimit(limit int32) {
	t.SessionConnectionLimit = limit
}

func (t *Target) SetWorkerFilter(filter string) {
	t.WorkerFilter = filter
}
