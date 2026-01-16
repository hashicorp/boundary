// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
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
	return "credential_vault_generic_library"
}

// SetTableName sets the table name.
func (l *CredentialLibrary) SetTableName(n string) {
	l.tableName = n
}

// GetResourceType returns the resource type of the CredentialLibrary
func (l *CredentialLibrary) GetResourceType() resource.Type {
	return resource.CredentialLibrary
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
func (l *CredentialLibrary) CredentialType() globals.CredentialType {
	switch ct := l.GetCredentialType(); ct {
	case "":
		return globals.UnspecifiedCredentialType
	default:
		return globals.CredentialType(ct)
	}
}

var _ credential.Library = (*CredentialLibrary)(nil)

// listCredentialLibraryResult represents the result of the
// list queries used to list all credential libraries.
type listCredentialLibraryResult struct {
	PublicId                  string
	StoreId                   string
	ProjectId                 string
	Name                      string
	Description               string
	VaultPath                 string
	CredentialType            string
	HttpMethod                string
	HttpRequestBody           string
	Username                  string
	KeyType                   string
	Ttl                       string
	KeyId                     string
	CriticalOptions           string
	Extensions                string
	AdditionalValidPrincipals string
	CreateTime                *timestamp.Timestamp
	UpdateTime                *timestamp.Timestamp
	Version                   int
	KeyBits                   int
	Type                      string
}

func (l *listCredentialLibraryResult) toLibrary(ctx context.Context) (credential.Library, error) {
	const op = "vault.(*listCredentialLibraryResult).toLibrary"
	switch l.Type {
	case "generic":
		cl := &CredentialLibrary{
			CredentialLibrary: &store.CredentialLibrary{
				PublicId:       l.PublicId,
				StoreId:        l.StoreId,
				Name:           l.Name,
				Description:    l.Description,
				CreateTime:     l.CreateTime,
				UpdateTime:     l.UpdateTime,
				Version:        uint32(l.Version),
				VaultPath:      l.VaultPath,
				CredentialType: l.CredentialType,
				HttpMethod:     l.HttpMethod,
			},
		}
		// Assign byte slices only if the string isn't empty
		if l.HttpRequestBody != "" {
			cl.HttpRequestBody = []byte(l.HttpRequestBody)
		}
		return cl, nil
	case "ssh":
		return &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				PublicId:                  l.PublicId,
				StoreId:                   l.StoreId,
				Name:                      l.Name,
				Description:               l.Description,
				CreateTime:                l.CreateTime,
				UpdateTime:                l.UpdateTime,
				Version:                   uint32(l.Version),
				VaultPath:                 l.VaultPath,
				CredentialType:            l.CredentialType,
				Username:                  l.Username,
				KeyType:                   l.KeyType,
				KeyBits:                   uint32(l.KeyBits),
				Ttl:                       l.Ttl,
				KeyId:                     l.KeyId,
				CriticalOptions:           l.CriticalOptions,
				Extensions:                l.Extensions,
				AdditionalValidPrincipals: l.AdditionalValidPrincipals,
			},
		}, nil
	case "ldap":
		return &LdapCredentialLibrary{
			LdapCredentialLibrary: &store.LdapCredentialLibrary{
				PublicId:       l.PublicId,
				StoreId:        l.StoreId,
				Name:           l.Name,
				Description:    l.Description,
				CreateTime:     l.CreateTime,
				UpdateTime:     l.UpdateTime,
				Version:        uint32(l.Version),
				VaultPath:      l.VaultPath,
				CredentialType: l.CredentialType,
			},
		}, nil
	default:
		return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("unexpected vault credential library type %s returned", l.Type))
	}
}

type deletedCredentialLibrary struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedCredentialLibrary) TableName() string {
	return "credential_vault_generic_library_deleted"
}
