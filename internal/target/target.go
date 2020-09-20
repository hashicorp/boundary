package target

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target/store"
)

// Target is a commmon interface for all target subtypes
type Target interface {
	GetPublicId() string
	GetScopeId() string
	GetDefaultPort() uint32
	GetName() string
	GetDescription() string
	GetVersion() uint32
	GetType() string
	GetCreateTime() *timestamp.Timestamp
	GetUpdateTime() *timestamp.Timestamp
	GetSessionMaxSeconds() uint32
	GetSessionConnectionLimit() int32
	oplog(op oplog.OpType) oplog.Metadata
}

// TargetType defines the possible types for targets.
type TargetType uint32

const (
	UnknownTargetType TargetType = 0
	TcpTargetType     TargetType = 1
)

// String returns a string representation of the target type.
func (t TargetType) String() string {
	return [...]string{
		"unknown",
		"tcp",
	}[t]
}

const (
	targetsViewDefaultTable = "target_all_subtypes"
)

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

// targetSubType converts the target view to the concrete subtype
func (t *targetView) targetSubType() (Target, error) {
	switch t.Type {
	case TcpTargetType.String():
		tcpTarget := allocTcpTarget()
		tcpTarget.PublicId = t.PublicId
		tcpTarget.ScopeId = t.ScopeId
		tcpTarget.Name = t.Name
		tcpTarget.Description = t.Description
		tcpTarget.DefaultPort = t.DefaultPort
		tcpTarget.CreateTime = t.CreateTime
		tcpTarget.UpdateTime = t.UpdateTime
		tcpTarget.Version = t.Version
		tcpTarget.SessionMaxSeconds = t.SessionMaxSeconds
		tcpTarget.SessionConnectionLimit = t.SessionConnectionLimit
		return &tcpTarget, nil
	}
	return nil, fmt.Errorf("%s is an unknown target subtype of %s", t.PublicId, t.Type)
}
