// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	goerrs "errors"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ServerCertificate holds the PEM encoded certificate and key for a target
type ServerCertificate struct {
	CertificatePem []byte
	PrivateKeyPem  []byte
}

// Target is a commmon interface for all target subtypes
type Target interface {
	GetPublicId() string
	GetProjectId() string
	GetDefaultPort() uint32
	GetDefaultClientPort() uint32
	GetName() string
	GetDescription() string
	GetVersion() uint32
	GetType() globals.Subtype
	GetResourceType() resource.Type
	GetCreateTime() *timestamp.Timestamp
	GetUpdateTime() *timestamp.Timestamp
	GetSessionMaxSeconds() uint32
	GetSessionConnectionLimit() int32
	GetWorkerFilter() string
	GetEgressWorkerFilter() string
	GetIngressWorkerFilter() string
	GetAddress() string
	GetAliases() []*target.Alias
	GetHostSources() []HostSource
	GetCredentialSources() []CredentialSource
	GetStorageBucketId() string
	GetEnableSessionRecording() bool
	GetProxyServerCertificate() *ServerCertificate
	Clone() Target
	SetPublicId(context.Context, string) error
	SetProjectId(string)
	SetName(string)
	SetDescription(string)
	SetVersion(uint32)
	SetDefaultPort(uint32)
	SetDefaultClientPort(uint32)
	SetCreateTime(*timestamp.Timestamp)
	SetUpdateTime(*timestamp.Timestamp)
	SetSessionMaxSeconds(uint32)
	SetSessionConnectionLimit(int32)
	SetWorkerFilter(string)
	SetEgressWorkerFilter(string)
	SetIngressWorkerFilter(string)
	SetAddress(string)
	SetAliases([]*target.Alias)
	SetHostSources([]HostSource)
	SetCredentialSources([]CredentialSource)
	SetStorageBucketId(string)
	SetEnableSessionRecording(bool)
	Oplog(op oplog.OpType) oplog.Metadata
	SetProxyServerCertificate(*ServerCertificate)
}

const (
	targetsViewDefaultTable = "target_all_subtypes"
)

var (
	_ boundary.AuthzProtectedEntity = (*targetView)(nil)

	errTargetSubtypeNotFound = goerrs.New("target subtype not found")
)

// targetView provides a common way to return targets regardless of their
// underlying type.
type targetView struct {
	*store.TargetView
	// Network address assigned to the Target.
	Address           string             `json:"address,omitempty" gorm:"-"`
	tableName         string             `gorm:"-"`
	HostSource        []HostSource       `gorm:"-"`
	CredentialSources []CredentialSource `gorm:"-"`
	Aliases           []*target.Alias    `gorm:"-"`
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

// GetResourceType returns the resource type of the Target
func (t *targetView) GetResourceType() resource.Type {
	return resource.Target
}

func (t *targetView) SetHostSources(hs []HostSource) {
	t.HostSource = hs
}

func (t *targetView) SetCredentialSources(cs []CredentialSource) {
	t.CredentialSources = cs
}

// GetPublicId satisfies boundary.AuthzProtectedEntity
func (t targetView) GetPublicId() string {
	return t.PublicId
}

// GetProjectId satisfies boundary.AuthzProtectedEntity
func (t targetView) GetProjectId() string {
	return t.ProjectId
}

func (t *targetView) GetHostSources() []HostSource {
	return t.HostSource
}

func (t *targetView) GetCredentialSources() []CredentialSource {
	return t.CredentialSources
}

// GetUserId satisfies boundary.AuthzProtectedEntity; targets are not associated
// with a user ID so this always returns an empty string
func (t targetView) GetUserId() string {
	return ""
}

func (t *targetView) Subtype() globals.Subtype {
	return globals.Subtype(t.Type)
}

// targetSubtype converts the target view to the concrete subtype
func (t *targetView) targetSubtype(ctx context.Context, address string) (Target, error) {
	const op = "target.targetView.targetSubtype"

	alloc, ok := subtypeRegistry.allocFunc(t.Subtype())
	if !ok {
		return nil, errors.Wrap(ctx,
			errTargetSubtypeNotFound,
			op,
			errors.WithCode(errors.InvalidParameter),
			errors.WithMsg(fmt.Sprintf("%s is an unknown target subtype of %s", t.PublicId, t.Type)),
		)
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
	tt.SetDefaultClientPort(t.DefaultClientPort)
	tt.SetCreateTime(t.CreateTime)
	tt.SetUpdateTime(t.UpdateTime)
	tt.SetSessionMaxSeconds(t.SessionMaxSeconds)
	tt.SetSessionConnectionLimit(t.SessionConnectionLimit)
	tt.SetWorkerFilter(t.WorkerFilter)
	tt.SetEgressWorkerFilter(t.EgressWorkerFilter)
	tt.SetIngressWorkerFilter(t.IngressWorkerFilter)
	tt.SetAddress(address)
	tt.SetHostSources(t.HostSource)
	tt.SetCredentialSources(t.CredentialSources)
	tt.SetEnableSessionRecording(t.EnableSessionRecording)
	tt.SetStorageBucketId(t.StorageBucketId)
	return tt, nil
}

type deletedTarget struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedTarget) TableName() string {
	return "target_all_subtypes_deleted_view"
}
