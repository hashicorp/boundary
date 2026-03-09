// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

// A CredentialStore contains credentials. It is owned by a project.
type CredentialStore struct {
	*store.CredentialStore
	tableName string `gorm:"-"`
}

// NewCredentialStore creates a new in memory static CredentialStore assigned to projectId.
// Name and description are the only valid options. All other options are ignored.
func NewCredentialStore(projectId string, opt ...Option) (*CredentialStore, error) {
	opts := getOpts(opt...)
	cs := &CredentialStore{
		CredentialStore: &store.CredentialStore{
			ProjectId:   projectId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	return cs, nil
}

func allocCredentialStore() *CredentialStore {
	return &CredentialStore{
		CredentialStore: &store.CredentialStore{},
	}
}

func (cs *CredentialStore) clone() *CredentialStore {
	cp := proto.Clone(cs.CredentialStore)
	return &CredentialStore{
		CredentialStore: cp.(*store.CredentialStore),
	}
}

// TableName returns the table name.
func (cs *CredentialStore) TableName() string {
	if cs.tableName != "" {
		return cs.tableName
	}
	return "credential_static_store"
}

// SetTableName sets the table name.
func (cs *CredentialStore) SetTableName(n string) {
	cs.tableName = n
}

// GetResourceType returns the resource type of the CredentialStore
func (cs *CredentialStore) GetResourceType() resource.Type {
	return resource.CredentialStore
}

func (cs *CredentialStore) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{cs.PublicId},
		"resource-type":      []string{"credential-static-store"},
		"op-type":            []string{op.String()},
	}
	if cs.ProjectId != "" {
		metadata["project-id"] = []string{cs.ProjectId}
	}
	return metadata
}
