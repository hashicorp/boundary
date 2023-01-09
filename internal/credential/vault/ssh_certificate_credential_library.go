package vault

import (
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

const (
	KeyTypeEcdsa   = "ecdsa"
	KeyTypeEd25519 = "ed25519"
	KeyTypeRsa     = "rsa"
)

// A CredentialLibrary contains a Vault path and is owned by a credential
// store.
type SSHCertificateCredentialLibrary struct {
	*store.SSHCertificateCredentialLibrary
	tableName string `gorm:"-"`
}

// NewSSHCertificateCredentialLibrary creates a new in memory CredentialLibrary
// for a Vault backend at vaultPath assigned to storeId.
// Name, description, method, request body, credential type, and mapping
// override are the only valid options. All other options are ignored.
func NewSSHCertificateCredentialLibrary(storeId string, vaultPath string, username string, opt ...Option) (*SSHCertificateCredentialLibrary, error) {
	const op = "vault.NewSSHCertificateCredentialLibrary"
	opts := getOpts(opt...)

	l := &SSHCertificateCredentialLibrary{
		SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
			StoreId:         storeId,
			Name:            opts.withName,
			Description:     opts.withDescription,
			VaultPath:       vaultPath,
			Username:        username,
			KeyType:         opts.withKeyType,
			KeyBits:         opts.withKeyBits,
			Ttl:             opts.withTtl,
			KeyId:           opts.withKeyId,
			CriticalOptions: opts.withCriticalOptions,
			Extensions:      opts.withExtensions,
			CredentialType:  string(credential.SshCertificateType),
		},
	}

	return l, nil
}

func allocSSHCertificateCredentialLibrary() *SSHCertificateCredentialLibrary {
	return &SSHCertificateCredentialLibrary{
		SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{},
	}
}

func (l *SSHCertificateCredentialLibrary) clone() *SSHCertificateCredentialLibrary {
	cp := proto.Clone(l.SSHCertificateCredentialLibrary)
	return &SSHCertificateCredentialLibrary{
		SSHCertificateCredentialLibrary: cp.(*store.SSHCertificateCredentialLibrary),
	}
}

func (l *SSHCertificateCredentialLibrary) setId(i string) {
	l.PublicId = i
}

// TableName returns the table name.
func (l *SSHCertificateCredentialLibrary) TableName() string {
	if l.tableName != "" {
		return l.tableName
	}
	return "credential_vault_ssh_cert_library"
}

// SetTableName sets the table name.
func (l *SSHCertificateCredentialLibrary) SetTableName(n string) {
	l.tableName = n
}

func (l *SSHCertificateCredentialLibrary) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{l.PublicId},
		"resource-type":      []string{"credential-vault-ssh-cert-library"},
		"op-type":            []string{op.String()},
	}
	if l.StoreId != "" {
		metadata["store-id"] = []string{l.StoreId}
	}
	return metadata
}

// CredentialType returns the type of credential the library retrieves.
func (l *SSHCertificateCredentialLibrary) CredentialType() credential.Type {
	return credential.Type(l.SSHCertificateCredentialLibrary.CredentialType)
}

var _ credential.Library = (*SSHCertificateCredentialLibrary)(nil)
