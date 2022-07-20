package target

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

// Target is a commmon interface for all target subtypes
type Target interface {
	GetPublicId() string
	GetProjectId() string
	GetDefaultPort() uint32
	GetName() string
	GetDescription() string
	GetVersion() uint32
	GetType() subtypes.Subtype
	GetCreateTime() *timestamp.Timestamp
	GetUpdateTime() *timestamp.Timestamp
	GetSessionMaxSeconds() uint32
	GetSessionConnectionLimit() int32
	GetWorkerFilter() string
	Clone() Target
	SetPublicId(context.Context, string) error
	SetProjectId(string)
	SetName(string)
	SetDescription(string)
	SetVersion(uint32)
	SetDefaultPort(uint32)
	SetCreateTime(*timestamp.Timestamp)
	SetUpdateTime(*timestamp.Timestamp)
	SetSessionMaxSeconds(uint32)
	SetSessionConnectionLimit(int32)
	SetWorkerFilter(string)
	Oplog(op oplog.OpType) oplog.Metadata
}

const (
	targetsViewDefaultTable = "target_all_subtypes"
)

var _ boundary.AuthzProtectedEntity = (*targetView)(nil)

// targetView provides a common way to return targets regardless of their
// underlying type.
type targetView struct {
	*store.TargetView
	tableName string `gorm:"-"`
}

// allocTargetView will allocate a target view
func allocTargetView() targetView {
	return targetView{
		TargetView: &store.TargetView{},
	}
}

// TableName provides an overridden gorm table name for targets.
func (t *targetView) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return targetsViewDefaultTable
}

// SetTableName sets the table name for the resource.  If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (t *targetView) SetTableName(n string) {
	switch n {
	case "":
		t.tableName = targetsViewDefaultTable
	default:
		t.tableName = n
	}
}

// GetPublicId satisfies boundary.AuthzProtectedEntity
func (t targetView) GetPublicId() string {
	return t.PublicId
}

// GetProjectId satisfies boundary.AuthzProtectedEntity
func (t targetView) GetProjectId() string {
	return t.ProjectId
}

// GetUserId satisfies boundary.AuthzProtectedEntity; targets are not associated
// with a user ID so this always returns an empty string
func (t targetView) GetUserId() string {
	return ""
}

func (t *targetView) Subtype() subtypes.Subtype {
	return subtypes.Subtype(t.Type)
}

// targetSubtype converts the target view to the concrete subtype
func (t *targetView) targetSubtype(ctx context.Context) (Target, error) {
	const op = "target.targetView.targetSubtype"

	alloc, ok := subtypeRegistry.allocFunc(t.Subtype())
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unknown target subtype of %s", t.PublicId, t.Type))
	}

	tt := alloc()
	if err := tt.SetPublicId(ctx, t.PublicId); err != nil {
		return nil, err
	}
	tt.SetVersion(t.Version)
	tt.SetProjectId(t.ProjectId)
	tt.SetName(t.Name)
	tt.SetDescription(t.Description)
	tt.SetDefaultPort(t.DefaultPort)
	tt.SetCreateTime(t.CreateTime)
	tt.SetUpdateTime(t.UpdateTime)
	tt.SetSessionMaxSeconds(t.SessionMaxSeconds)
	tt.SetSessionConnectionLimit(t.SessionConnectionLimit)
	tt.SetWorkerFilter(t.WorkerFilter)
	return tt, nil
}
