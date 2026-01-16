// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db/sanitize"
	"github.com/hashicorp/boundary/internal/db/sentinel"
	"google.golang.org/protobuf/proto"
)

// validMappingOverride reports whether the given mapping override is valid
// for the given credential type.
func validMappingOverride(m MappingOverride, ct globals.CredentialType) bool {
	switch m.(type) {
	case nil:
		return true // it is always valid to not specify a mapping override
	case *UsernamePasswordOverride:
		return ct == globals.UsernamePasswordCredentialType
	case *UsernamePasswordDomainOverride:
		return ct == globals.UsernamePasswordDomainCredentialType
	case *PasswordOverride:
		return ct == globals.PasswordCredentialType
	case *SshPrivateKeyOverride:
		return ct == globals.SshPrivateKeyCredentialType
	default:
		return false // an unknown mapping override type is never valid
	}
}

// A MappingOverride is an interface holding one of the mapping override
// types: UsernamePasswordOverride.
type MappingOverride interface {
	clone() MappingOverride
	setLibraryId(i string)

	// sanitize replaces all sentinel values in the MappingOverride with
	// zero values. It is called before a MappingOverride is returned from
	// the domain layer when the MappingOverride has been loaded from the
	// database.
	sanitize()
}

// A UsernamePasswordOverride contains optional values for overriding the
// default mappings used to map a Vault secret to a UsernamePassword credential
// type for the credential library that owns it.
type UsernamePasswordOverride struct {
	*store.UsernamePasswordOverride
	tableName string `gorm:"-"`
}

var _ MappingOverride = (*UsernamePasswordOverride)(nil)

// NewUsernamePasswordOverride creates a new in memory UsernamePasswordOverride.
// WithOverrideUsernameAttribute and WithOverridePasswordAttribute are the
// only valid options. All other options are ignored.
func NewUsernamePasswordOverride(opt ...Option) *UsernamePasswordOverride {
	opts := getOpts(opt...)
	o := &UsernamePasswordOverride{
		UsernamePasswordOverride: &store.UsernamePasswordOverride{
			UsernameAttribute: sanitize.String(opts.withOverrideUsernameAttribute),
			PasswordAttribute: sanitize.String(opts.withOverridePasswordAttribute),
		},
	}
	return o
}

func allocUsernamePasswordOverride() *UsernamePasswordOverride {
	return &UsernamePasswordOverride{
		UsernamePasswordOverride: &store.UsernamePasswordOverride{},
	}
}

func (o *UsernamePasswordOverride) clone() MappingOverride {
	cp := proto.Clone(o.UsernamePasswordOverride)
	return &UsernamePasswordOverride{
		UsernamePasswordOverride: cp.(*store.UsernamePasswordOverride),
	}
}

func (o *UsernamePasswordOverride) setLibraryId(i string) {
	o.LibraryId = i
}

func (o *UsernamePasswordOverride) sanitize() {
	if sentinel.Is(o.UsernameAttribute) {
		o.UsernameAttribute = ""
	}
	if sentinel.Is(o.PasswordAttribute) {
		o.PasswordAttribute = ""
	}
}

// TableName returns the table name.
func (o *UsernamePasswordOverride) TableName() string {
	if o.tableName != "" {
		return o.tableName
	}
	return "credential_vault_generic_library_username_password_mapping_ovrd"
}

// SetTableName sets the table name.
func (o *UsernamePasswordOverride) SetTableName(n string) {
	o.tableName = n
}

// A UsernamePasswordDomainOverride contains optional values for overriding the
// default mappings used to map a Vault secret to a UsernamePasswordDomain credential
// type for the credential library that owns it.
type UsernamePasswordDomainOverride struct {
	*store.UsernamePasswordDomainOverride
	tableName string `gorm:"-"`
}

var _ MappingOverride = (*UsernamePasswordDomainOverride)(nil)

// NewUsernameDomainPasswordOverride creates a new in memory UsernamePasswordDomainOverride.
// WithOverrideUsernameAttribute, WithOverridePasswordAttribute, and WithOverrideDomainAttribute are the
// only valid options. All other options are ignored.
func NewUsernamePasswordDomainOverride(opt ...Option) *UsernamePasswordDomainOverride {
	opts := getOpts(opt...)
	o := &UsernamePasswordDomainOverride{
		UsernamePasswordDomainOverride: &store.UsernamePasswordDomainOverride{
			UsernameAttribute: sanitize.String(opts.withOverrideUsernameAttribute),
			PasswordAttribute: sanitize.String(opts.withOverridePasswordAttribute),
			DomainAttribute:   sanitize.String(opts.withOverrideDomainAttribute),
		},
	}
	return o
}

func allocUsernamePasswordDomainOverride() *UsernamePasswordDomainOverride {
	return &UsernamePasswordDomainOverride{
		UsernamePasswordDomainOverride: &store.UsernamePasswordDomainOverride{},
	}
}

func (o *UsernamePasswordDomainOverride) clone() MappingOverride {
	cp := proto.Clone(o.UsernamePasswordDomainOverride)
	return &UsernamePasswordDomainOverride{
		UsernamePasswordDomainOverride: cp.(*store.UsernamePasswordDomainOverride),
	}
}

func (o *UsernamePasswordDomainOverride) setLibraryId(i string) {
	o.LibraryId = i
}

func (o *UsernamePasswordDomainOverride) sanitize() {
	if sentinel.Is(o.UsernameAttribute) {
		o.UsernameAttribute = ""
	}
	if sentinel.Is(o.PasswordAttribute) {
		o.PasswordAttribute = ""
	}
	if sentinel.Is(o.DomainAttribute) {
		o.DomainAttribute = ""
	}
}

// TableName returns the table name.
func (o *UsernamePasswordDomainOverride) TableName() string {
	if o.tableName != "" {
		return o.tableName
	}
	return "credential_vault_generic_library_usern_pass_domain_mapping_ovrd"
}

// SetTableName sets the table name.
func (o *UsernamePasswordDomainOverride) SetTableName(n string) {
	o.tableName = n
}

// A PasswordOverride contains optional values for overriding the
// default mappings used to map a Vault secret to a Password credential
// type for the credential library that owns it.
type PasswordOverride struct {
	*store.PasswordOverride
	tableName string `gorm:"-"`
}

var _ MappingOverride = (*PasswordOverride)(nil)

// NewPasswordOverride creates a new in memory PasswordOverride.
// WithOverrideAttribute and WithOverridePasswordAttribute are the
// only valid options. All other options are ignored.
func NewPasswordOverride(opt ...Option) *PasswordOverride {
	opts := getOpts(opt...)
	o := &PasswordOverride{
		PasswordOverride: &store.PasswordOverride{
			PasswordAttribute: sanitize.String(opts.withOverridePasswordAttribute),
		},
	}
	return o
}

func allocPasswordOverride() *PasswordOverride {
	return &PasswordOverride{
		PasswordOverride: &store.PasswordOverride{},
	}
}

func (o *PasswordOverride) clone() MappingOverride {
	cp := proto.Clone(o.PasswordOverride)
	return &PasswordOverride{
		PasswordOverride: cp.(*store.PasswordOverride),
	}
}

func (o *PasswordOverride) setLibraryId(i string) {
	o.LibraryId = i
}

func (o *PasswordOverride) sanitize() {
	if sentinel.Is(o.PasswordAttribute) {
		o.PasswordAttribute = ""
	}
}

// TableName returns the table name.
func (o *PasswordOverride) TableName() string {
	if o.tableName != "" {
		return o.tableName
	}
	return "credential_vault_generic_library_password_mapping_override"
}

// SetTableName sets the table name.
func (o *PasswordOverride) SetTableName(n string) {
	o.tableName = n
}

// A SshPrivateKeyOverride contains optional values for overriding the
// default mappings used to map a Vault secret to a SshPrivateKey credential
// type for the credential library that owns it.
type SshPrivateKeyOverride struct {
	*store.SshPrivateKeyOverride
	tableName string `gorm:"-"`
}

var _ MappingOverride = (*SshPrivateKeyOverride)(nil)

// NewSshPrivateKeyOverride creates a new in memory SshPrivateKeyOverride.
// WithOverrideUsernameAttribute, WithOverridePrivateKeyAttribute and WithOverridePrivateKeyPassphraseAttribute
// are the only valid options. All other options are ignored.
func NewSshPrivateKeyOverride(opt ...Option) *SshPrivateKeyOverride {
	opts := getOpts(opt...)
	o := &SshPrivateKeyOverride{
		SshPrivateKeyOverride: &store.SshPrivateKeyOverride{
			UsernameAttribute:             sanitize.String(opts.withOverrideUsernameAttribute),
			PrivateKeyAttribute:           sanitize.String(opts.withOverridePrivateKeyAttribute),
			PrivateKeyPassphraseAttribute: sanitize.String(opts.withOverridePrivateKeyPassphraseAttribute),
		},
	}
	return o
}

func allocSshPrivateKeyOverride() *SshPrivateKeyOverride {
	return &SshPrivateKeyOverride{
		SshPrivateKeyOverride: &store.SshPrivateKeyOverride{},
	}
}

func (o *SshPrivateKeyOverride) clone() MappingOverride {
	cp := proto.Clone(o.SshPrivateKeyOverride)
	return &SshPrivateKeyOverride{
		SshPrivateKeyOverride: cp.(*store.SshPrivateKeyOverride),
	}
}

func (o *SshPrivateKeyOverride) setLibraryId(i string) {
	o.LibraryId = i
}

func (o *SshPrivateKeyOverride) sanitize() {
	if sentinel.Is(o.UsernameAttribute) {
		o.UsernameAttribute = ""
	}
	if sentinel.Is(o.PrivateKeyAttribute) {
		o.PrivateKeyAttribute = ""
	}
	if sentinel.Is(o.PrivateKeyPassphraseAttribute) {
		o.PrivateKeyPassphraseAttribute = ""
	}
}

// TableName returns the table name.
func (o *SshPrivateKeyOverride) TableName() string {
	if o.tableName != "" {
		return o.tableName
	}
	return "credential_vault_generic_library_ssh_private_key_mapping_ovrd"
}

// SetTableName sets the table name.
func (o *SshPrivateKeyOverride) SetTableName(n string) {
	o.tableName = n
}
