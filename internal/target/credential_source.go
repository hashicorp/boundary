package target

import (
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/target/store"
)

var _ CredentialSource = (*TargetCredentialSource)(nil)

// CredentialSource is an interface that can be implemented by both a library
// and a singular credential.
type CredentialSource interface {
	CredentialStoreId() string
	Id() string
	CredentialPurpose() credential.Purpose
	TargetId() string
}

// CredentialSources contains slices of credential publicIds
// per purpose to be attacehd to the target.
type CredentialSources struct {
	ApplicationCredentialIds []string
	EgressCredentialIds      []string
}

// A TargetCredentialSource represents the relationship between a target and a
// credential library and includes the id of the credential store that the
// library is a part of and the library's name and description.
//
// It implements the target.CredentialSource interface.
type TargetCredentialSource struct {
	*store.CredentialSource
	StoreId string
}

// TableName returns the tablename to override the default gorm table name
func (ts *TargetCredentialSource) TableName() string {
	return "target_credential_source"
}

// Id returns the ID of the credential source
func (ts *TargetCredentialSource) Id() string {
	return ts.CredentialSourceId
}

// CredentialStoreId returns the ID of the store containing the credential source
func (ts *TargetCredentialSource) CredentialStoreId() string {
	return ts.StoreId
}

// CredentialPurpose returns the purpose of the credential
func (ts *TargetCredentialSource) CredentialPurpose() credential.Purpose {
	return credential.Purpose(ts.GetCredentialPurpose())
}

// TargetId returns the target linked to this credential source
func (ts *TargetCredentialSource) TargetId() string {
	return ts.GetTargetId()
}

// credentialView provides a common way to return credentials regardless of their
// underlying type.
type credentialView struct {
	*store.CredentialView
	tableName string `gorm:"-"`
}

// TableName returns the tablename to override the default gorm table name
func (ts *credentialView) TableName() string {
	return "credential_source_all_types"
}
