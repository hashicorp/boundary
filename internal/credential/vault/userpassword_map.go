package vault

import (
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// UserPasswordMap contains values for mapping Vault secrets to
// UserPassword credentials for the specified credential library.
type UserPasswordMap struct {
	*store.UserPasswordMap
	tableName string `gorm:"-"`
}

// NewUserPasswordMap creates a new in memory UserPasswordMap assigned to
// libraryId. Username is the name of the attribute in a Vault secret that
// maps to the username in a UserPassword credential. Password is the name
// of the attribute in a Vault secret that maps to the password in a
// UserPassword credential.
func NewUserPasswordMap(libraryId string, username, password string) *UserPasswordMap {
	u := &UserPasswordMap{
		UserPasswordMap: &store.UserPasswordMap{
			LibraryId: libraryId,
			Username:  username,
			Password:  password,
		},
	}
	return u
}

func allocUserPasswordMap() *UserPasswordMap {
	return &UserPasswordMap{
		UserPasswordMap: &store.UserPasswordMap{},
	}
}

func (u *UserPasswordMap) clone() *UserPasswordMap {
	cp := proto.Clone(u.UserPasswordMap)
	return &UserPasswordMap{
		UserPasswordMap: cp.(*store.UserPasswordMap),
	}
}

// TableName returns the table name.
func (u *UserPasswordMap) TableName() string {
	if u.tableName != "" {
		return u.tableName
	}
	return "credential_vault_library_user_password_map"
}

// SetTableName sets the table name.
func (u *UserPasswordMap) SetTableName(n string) {
	u.tableName = n
}

func (u *UserPasswordMap) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-private-id": []string{u.PrivateId},
		"resource-type":       []string{"vault-user-password-map"},
		"op-type":             []string{op.String()},
	}
	if u.LibraryId != "" {
		metadata["library-id"] = []string{u.LibraryId}
	}
	return metadata
}
