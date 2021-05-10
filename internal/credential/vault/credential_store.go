package vault

import (
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A CredentialStore contains credential libraries. It is owned by a scope.
type CredentialStore struct {
	*store.CredentialStore
	tableName string `gorm:"-"`

	clientCert  *ClientCertificate `gorm:"-"`
	inputToken  []byte             `gorm:"-"`
	outputToken *Token             `gorm:"-"`

	privateClientCert *ClientCertificate `gorm:"-"`
	privateToken      *Token             `gorm:"-"`
}

// NewCredentialStore creates a new in memory CredentialStore for a Vault
// server at vaultAddress assigned to scopeId. Name, description, CA cert,
// client cert, namespace, TLS server name, and TLS skip verify are the
// only valid options. All other options are ignored.
func NewCredentialStore(scopeId string, vaultAddress string, token []byte, opt ...Option) (*CredentialStore, error) {
	opts := getOpts(opt...)
	cs := &CredentialStore{
		inputToken: token,
		clientCert: opts.withClientCert,
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
	tokenCopy := make([]byte, len(cs.inputToken))
	copy(tokenCopy, cs.inputToken)
	var clientCertCopy *ClientCertificate
	if cs.clientCert != nil {
		clientCertCopy = cs.clientCert.clone()
	}
	cp := proto.Clone(cs.CredentialStore)
	return &CredentialStore{
		inputToken:      tokenCopy,
		clientCert:      clientCertCopy,
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
		"resource-type":      []string{"credential-vault-store"},
		"op-type":            []string{op.String()},
	}
	if cs.ScopeId != "" {
		metadata["scope-id"] = []string{cs.ScopeId}
	}
	return metadata
}

// Token returns the current vault token if available.
func (cs *CredentialStore) Token() *Token {
	return cs.outputToken
}

// ClientCertificate returns the client certificate if available.
func (cs *CredentialStore) ClientCertificate() *ClientCertificate {
	return cs.clientCert
}
