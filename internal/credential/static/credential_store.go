package static

import (
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A CredentialStore contains credentials. It is owned by a scope.
type CredentialStore struct {
	*store.CredentialStore
	tableName string `gorm:"-"`
}

// NewCredentialStore creates a new in memory static CredentialStore assigned to scopeId.
// Name and description are the only valid options. All other options are ignored.
func NewCredentialStore(scopeId string, opt ...Option) (*CredentialStore, error) {
	opts := getOpts(opt...)
	cs := &CredentialStore{
		CredentialStore: &store.CredentialStore{
			ScopeId:     scopeId,
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

func (cs *CredentialStore) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{cs.PublicId},
		"resource-type":      []string{"credential-static-store"},
		"op-type":            []string{op.String()},
	}
	if cs.ScopeId != "" {
		metadata["scope-id"] = []string{cs.ScopeId}
	}
	return metadata
}
