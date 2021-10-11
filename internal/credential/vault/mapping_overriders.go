package vault

import (
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db/sanitize"
	"google.golang.org/protobuf/proto"
)

// validMappingOverride reports whether the given mapping override is valid
// for the given credential type.
func validMappingOverride(m MappingOverride, ct credential.Type) bool {
	switch m.(type) {
	case nil:
		return true // it is always valid to not specify a mapping override
	case *UserPasswordOverride:
		return ct == credential.UserPasswordType
	default:
		return false // an unknown mapping override type is never valid
	}
}

// A MappingOverride is an interface holding one of the mapping override
// types: UserPasswordOverride.
type MappingOverride interface {
	clone() MappingOverride
	libraryId(i string)
}

// A UserPasswordOverride contains optional values for overriding the
// default mappings used to map a Vault secret to a UserPassword credential
// type for the credential library that owns it.
type UserPasswordOverride struct {
	*store.UserPasswordOverride
	tableName string `gorm:"-"`
}

var _ MappingOverride = (*UserPasswordOverride)(nil)

// NewUserPasswordOverride creates a new in memory UserPasswordOverride.
// WithOverrideUsernameAttribute and WithOverridePasswordAttribute are the
// only valid options. All other options are ignored.
func NewUserPasswordOverride(opt ...Option) *UserPasswordOverride {
	opts := getOpts(opt...)
	o := &UserPasswordOverride{
		UserPasswordOverride: &store.UserPasswordOverride{
			UsernameAttribute: sanitize.String(opts.withOverrideUsernameAttribute),
			PasswordAttribute: sanitize.String(opts.withOverridePasswordAttribute),
		},
	}
	return o
}

func allocUserPasswordOverride() *UserPasswordOverride {
	return &UserPasswordOverride{
		UserPasswordOverride: &store.UserPasswordOverride{},
	}
}

func (o *UserPasswordOverride) clone() MappingOverride {
	cp := proto.Clone(o.UserPasswordOverride)
	return &UserPasswordOverride{
		UserPasswordOverride: cp.(*store.UserPasswordOverride),
	}
}

func (o *UserPasswordOverride) libraryId(i string) {
	o.LibraryId = i
}

// TableName returns the table name.
func (o *UserPasswordOverride) TableName() string {
	if o.tableName != "" {
		return o.tableName
	}
	return "credential_vault_library_user_password_mapping_override"
}

// SetTableName sets the table name.
func (o *UserPasswordOverride) SetTableName(n string) {
	o.tableName = n
}
