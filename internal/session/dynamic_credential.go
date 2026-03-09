// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	cred "github.com/hashicorp/boundary/internal/credential"
)

// A DynamicCredential represents the relationship between a session, a
// credential, and the credential library where the credential was
// retrieved plus the purpose of the credential.
type DynamicCredential struct {
	SessionId         string `json:"session_id,omitempty" gorm:"primary_key"`
	LibraryId         string `json:"library_id,omitempty" gorm:"primary_key"`
	CredentialPurpose string `json:"credential_purpose,omitempty" gorm:"primary_key"`
	CredentialId      string `json:"credential_id,omitempty" gorm:"default:null"`

	tableName string `gorm:"-"`
}

// NewDynamicCredential creates a new in memory Credential representing the
// relationship between session and a credential library.
func NewDynamicCredential(libraryId string, purpose cred.Purpose) *DynamicCredential {
	return &DynamicCredential{
		LibraryId:         libraryId,
		CredentialPurpose: string(purpose),
	}
}

func allocCredential() *DynamicCredential {
	return &DynamicCredential{}
}

func (c *DynamicCredential) clone() *DynamicCredential {
	return &DynamicCredential{
		SessionId:         c.SessionId,
		LibraryId:         c.LibraryId,
		CredentialPurpose: c.CredentialPurpose,
		CredentialId:      c.CredentialId,
	}
}

// TableName returns the table name.
func (c *DynamicCredential) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "session_credential_dynamic"
}

// SetTableName sets the table name.
func (c *DynamicCredential) SetTableName(n string) {
	c.tableName = n
}
