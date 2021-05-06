package session

import (
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target"
)

// A DynamicCredential represents the relationship between a session, a
// credential, and the credential library where the credential was
// retrieved plus the purpose of the credential.
type DynamicCredential struct {
	SessionId         string `json:"session_id,omitempty" gorm:"primary_key"`
	CredentialId      string `json:"credential_id,omitempty" gorm:"primary_key"`
	LibraryId         string `json:"library_id,omitempty" gorm:"primary_key"`
	CredentialPurpose string `json:"credential_purpose,omitempty" gorm:"default:null"`

	tableName string `gorm:"-"`
}

// NewDynamicCredential creates a new in memory Credential representing the
// relationship between sessionId, credentialId, and library.
func NewDynamicCredential(sessionId, credentialId string, library *target.CredentialLibrary, _ ...Option) (*DynamicCredential, error) {
	const op = "session.NewDynamicCredential"
	if sessionId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no session id")
	}
	if credentialId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no credential id")
	}
	if library == nil {
		return nil, errors.New(errors.InvalidParameter, op, "no target credential library")
	}
	if library.GetCredentialLibraryId() == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no library id in target library")
	}
	if library.GetCredentialPurpose() == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no credential purpose in target library")
	}

	c := &DynamicCredential{
		SessionId:         sessionId,
		CredentialId:      credentialId,
		LibraryId:         library.GetCredentialLibraryId(),
		CredentialPurpose: library.GetCredentialPurpose(),
	}
	return c, nil
}

func allocCredential() *DynamicCredential {
	return &DynamicCredential{}
}

func (c *DynamicCredential) clone() *DynamicCredential {
	return &DynamicCredential{}
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
