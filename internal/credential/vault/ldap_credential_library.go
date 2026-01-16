// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

var _ credential.Library = (*LdapCredentialLibrary)(nil)

// LdapCredentialLibrary is a credential library that issues ldap credentials
// using the vault ldap secret engine. This credential library always issues
// username/password/domain credentials.
type LdapCredentialLibrary struct {
	*store.LdapCredentialLibrary
	tableName string `gorm:"-"`
}

// NewLdapCredentialLibrary creates a new in memory LdapCredentialLibrary for a
// Vault backend at vaultPath assigned to storeId. This credential library
// always issues username/password/domain credentials. WithName and
// WithDescription are the only valid options. All other options are ignored.
func NewLdapCredentialLibrary(storeId string, vaultPath string, opt ...Option) (*LdapCredentialLibrary, error) {
	const op = "vault.NewLdapCredentialLibrary"
	opts := getOpts(opt...)

	l := &LdapCredentialLibrary{
		LdapCredentialLibrary: &store.LdapCredentialLibrary{
			StoreId:        storeId,
			Name:           opts.withName,
			Description:    opts.withDescription,
			VaultPath:      vaultPath,
			CredentialType: string(globals.UsernamePasswordDomainCredentialType),
		},
	}

	return l, nil
}

func allocLdapCredentialLibrary() *LdapCredentialLibrary {
	return &LdapCredentialLibrary{
		LdapCredentialLibrary: &store.LdapCredentialLibrary{},
	}
}

func (l *LdapCredentialLibrary) clone() *LdapCredentialLibrary {
	cp := proto.Clone(l.LdapCredentialLibrary)
	return &LdapCredentialLibrary{
		LdapCredentialLibrary: cp.(*store.LdapCredentialLibrary),
	}
}

func (l *LdapCredentialLibrary) setId(i string) {
	l.PublicId = i
}

// TableName returns the table name.
func (l *LdapCredentialLibrary) TableName() string {
	if l.tableName != "" {
		return l.tableName
	}
	return "credential_vault_ldap_library"
}

// SetTableName sets the table name.
func (l *LdapCredentialLibrary) SetTableName(n string) {
	l.tableName = n
}

// GetResourceType returns the resource type of the CredentialLibrary
func (l *LdapCredentialLibrary) GetResourceType() resource.Type {
	return resource.CredentialLibrary
}

func (l *LdapCredentialLibrary) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{l.PublicId},
		"resource-type":      []string{"credential-vault-ldap-library"},
		"op-type":            []string{op.String()},
	}
	if l.StoreId != "" {
		metadata["store-id"] = []string{l.StoreId}
	}
	return metadata
}

// CredentialType returns the type of credential the library retrieves.
func (l *LdapCredentialLibrary) CredentialType() globals.CredentialType {
	return globals.CredentialType(l.LdapCredentialLibrary.CredentialType)
}

type deletedLdapCredentialLibrary struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedLdapCredentialLibrary) TableName() string {
	return "credential_vault_ldap_library_deleted"
}
