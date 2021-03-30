package vault

import (
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A CredentialStore contains credential libraries. It is owned by a scope.
type CredentialStore struct {
	*store.CredentialStore
	tableName string `gorm:"-"`
}

// NewCredentialStore creates a new in memory CredentialStore for a Vault
// server at vaultAddress assigned to scopeId.
// Name, description, CA cert, namespace, TLS server name, and TLS skip
// verify are the only valid options.
// All other options are ignored.
func NewCredentialStore(scopeId string, vaultAddress string, vaultToken string, opt ...Option) (*CredentialStore, error) {
	const op = "vault.NewCredentialStore"
	if scopeId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no scope id")
	}
	if vaultAddress == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no vault address")
	}
	if vaultToken == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no vault token")
	}

	// TODO(mgaffney) 03/2021: handle vaultToken

	opts := getOpts(opt...)
	cs := &CredentialStore{
		CredentialStore: &store.CredentialStore{
			ScopeId:       scopeId,
			Name:          opts.withName,
			Description:   opts.withDescription,
			VaultAddress:  vaultAddress,
			CaCert:        opts.withCACert,
			Namespace:     opts.withNamespace,
			TlsServerName: opts.withTlsServerName,
			TlsSkipVerify: opts.withTlsSkipVerify,
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
	return "credential_vault_store"
}

// SetTableName sets the table name.
func (cs *CredentialStore) SetTableName(n string) {
	cs.tableName = n
}

func (cs *CredentialStore) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{cs.PublicId},
		"resource-type":      []string{"credential-store"},
		"op-type":            []string{op.String()},
	}
	if cs.ScopeId != "" {
		metadata["scope-id"] = []string{cs.ScopeId}
	}
	return metadata
}
