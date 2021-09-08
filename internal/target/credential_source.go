package target

import "github.com/hashicorp/boundary/internal/credential"

// CredentialSource is an interface that can be implemented by both a library
// and a singular credential.
type CredentialSource interface {
	CredentialStoreId() string
	Id() string
	CredentialPurpose() credential.Purpose
	TargetId() string
}
