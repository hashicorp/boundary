// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	cred "github.com/hashicorp/boundary/internal/credential"
)

// A StaticCredential represents the relationship between a session, a
// credential and the purpose of the credential.
type StaticCredential struct {
	SessionId          string `json:"session_id,omitempty" gorm:"primary_key"`
	CredentialPurpose  string `json:"credential_purpose,omitempty" gorm:"primary_key"`
	CredentialStaticId string `json:"credential_id,omitempty" gorm:"default:null"`

	tableName string `gorm:"-"`
}

// NewStaticCredential creates a new in memory Credential representing the
// relationship between session a credential and the purpose of the credential.
func NewStaticCredential(id string, purpose cred.Purpose) *StaticCredential {
	return &StaticCredential{
		CredentialStaticId: id,
		CredentialPurpose:  string(purpose),
	}
}

func (c *StaticCredential) clone() *StaticCredential {
	return &StaticCredential{
		SessionId:          c.SessionId,
		CredentialPurpose:  c.CredentialPurpose,
		CredentialStaticId: c.CredentialStaticId,
	}
}

// TableName returns the table name.
func (c *StaticCredential) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "session_credential_static"
}

// SetTableName sets the table name.
func (c *StaticCredential) SetTableName(n string) {
	c.tableName = n
}
