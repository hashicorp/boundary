// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package vault

import (
	"context"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A Method represents an HTTP method used for communicating with Vault.
type Method string

// HTTP methods use for communicating with Vault.
const (
	MethodGet  Method = "GET"
	MethodPost Method = "POST"
)

// A CredentialLibrary contains a Vault path and is owned by a credential
// store.
type CredentialLibrary struct {
	*store.CredentialLibrary
	tableName string `gorm:"-"`

	MappingOverride MappingOverride `gorm:"-"`
}

// NewCredentialLibrary creates a new in memory CredentialLibrary
// for a Vault backend at vaultPath assigned to storeId.
// Name, description, method, request body, credential type, and mapping
// override are the only valid options. All other options are ignored.
func NewCredentialLibrary(storeId string, vaultPath string, opt ...Option) (*CredentialLibrary, error) {
	const op = "vault.NewCredentialLibrary"
	opts := getOpts(opt...)

	l := &CredentialLibrary{
		MappingOverride: opts.withMappingOverride,
		CredentialLibrary: &store.CredentialLibrary{
			StoreId:         storeId,
			Name:            opts.withName,
			Description:     opts.withDescription,
			VaultPath:       vaultPath,
			HttpRequestBody: opts.withRequestBody,
			HttpMethod:      string(opts.withMethod),
			CredentialType:  string(opts.withCredentialType),
		},
	}

	return l, nil
}

func (l *CredentialLibrary) validate(ctx context.Context, caller errors.Op) error {
	switch {
	case !validMappingOverride(l.MappingOverride, l.CredentialType()):
		return errors.New(ctx, errors.VaultInvalidMappingOverride, caller, "invalid credential type for mapping override")
	}
	return nil
}

func allocCredentialLibrary() *CredentialLibrary {
	return &CredentialLibrary{
		CredentialLibrary: &store.CredentialLibrary{},
	}
}

func (l *CredentialLibrary) clone() *CredentialLibrary {
	var m MappingOverride
	if l.MappingOverride != nil {
		m = l.MappingOverride.clone()
	}

	cp := proto.Clone(l.CredentialLibrary)
	return &CredentialLibrary{
		MappingOverride:   m,
		CredentialLibrary: cp.(*store.CredentialLibrary),
	}
}

func (l *CredentialLibrary) setId(i string) {
	l.PublicId = i
	if l.MappingOverride != nil {
		l.MappingOverride.setLibraryId(i)
	}
}

// TableName returns the table name.
func (l *CredentialLibrary) TableName() string {
	if l.tableName != "" {
		return l.tableName
	}
	return "credential_vault_library"
}

// SetTableName sets the table name.
func (l *CredentialLibrary) SetTableName(n string) {
	l.tableName = n
}

func (l *CredentialLibrary) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{l.PublicId},
		"resource-type":      []string{"credential-vault-library"},
		"op-type":            []string{op.String()},
	}
	if l.StoreId != "" {
		metadata["store-id"] = []string{l.StoreId}
	}
	return metadata
}

// CredentialType returns the type of credential the library retrieves.
func (l *CredentialLibrary) CredentialType() credential.Type {
	switch ct := l.GetCredentialType(); ct {
	case "":
		return credential.UnspecifiedType
	default:
		return credential.Type(ct)
	}
}

var _ credential.Library = (*CredentialLibrary)(nil)
