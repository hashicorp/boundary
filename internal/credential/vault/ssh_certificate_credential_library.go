// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

	KeyBitsDefault = 0

	KeyBitsEcdsa256 = 256
	KeyBitsEcdsa384 = 384
	KeyBitsEcdsa521 = 521

	KeyBitsRsa2048 = 2048
	KeyBitsRsa3072 = 3072
	KeyBitsRsa4096 = 4096
)

// SSHCertificateCredentialLibrary is a credential library that issues
// ssh certificate using the vault ssh secret engine.
// See: https://developer.hashicorp.com/vault/api-docs/secret/ssh#sign-ssh-key
type SSHCertificateCredentialLibrary struct {
	*store.SSHCertificateCredentialLibrary
	tableName string `gorm:"-"`
}

// NewSSHCertificateCredentialLibrary creates a new in memory SSHCertificateCredentialLibrary
// for a Vault backend at vaultPath assigned to storeId. The SSH username field must be set.
// Name, description, key type, key bits, ttl, key id, critical options, and extensions
// are the only valid options. All other options are ignored.
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

func (l *SSHCertificateCredentialLibrary) getDefaultKeyBits() uint32 {
	switch l.KeyType {
	case KeyTypeEcdsa:
		return KeyBitsEcdsa256
	case KeyTypeRsa:
		return KeyBitsRsa2048
	default:
		return KeyBitsDefault
	}
}

// CredentialType returns the type of credential the library retrieves.
func (l *SSHCertificateCredentialLibrary) CredentialType() credential.Type {
	return credential.Type(l.SSHCertificateCredentialLibrary.CredentialType)
}

var _ credential.Library = (*SSHCertificateCredentialLibrary)(nil)
