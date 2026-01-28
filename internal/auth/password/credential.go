// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A Credential is a base type and contains the attributes common to all
// credentials.
type Credential struct {
	*store.Credential
	tableName string `gorm:"-"`
}

func allocCredential() Credential {
	return Credential{
		Credential: &store.Credential{},
	}
}

func (c *Credential) clone() *Credential {
	cp := proto.Clone(c.Credential)
	return &Credential{
		Credential: cp.(*store.Credential),
	}
}

// TableName returns the table name.
func (c *Credential) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "auth_password_credential"
}

// SetTableName sets the table name.
func (c *Credential) SetTableName(n string) {
	c.tableName = n
}

func (c *Credential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.PrivateId},
		"resource-type":      []string{"password-credential"},
		"op-type":            []string{op.String()},
	}
	if c.PasswordAccountId != "" {
		metadata["account-id"] = []string{c.PasswordAccountId}
	}
	return metadata
}
