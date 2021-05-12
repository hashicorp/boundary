package credential

import (
	"strings"

	"github.com/hashicorp/boundary/internal/credential/vault"
)

type SubType int

const (
	UnknownSubtype SubType = iota
	VaultSubtype
)

func (t SubType) String() string {
	switch t {
	case VaultSubtype:
		return "vault"
	}
	return "unknown"
}

// Subtype uses the provided subtype
func SubtypeFromType(t string) SubType {
	switch {
	case strings.EqualFold(strings.TrimSpace(t), VaultSubtype.String()):
		return VaultSubtype
	}
	return UnknownSubtype
}

func SubtypeFromId(id string) SubType {
	switch {
	case strings.HasPrefix(strings.TrimSpace(id), vault.CredentialStorePrefix),
		strings.HasPrefix(strings.TrimSpace(id), vault.CredentialLibraryPrefix),
		strings.HasPrefix(strings.TrimSpace(id), vault.DynamicCredentialPrefix):
		return VaultSubtype
	}
	return UnknownSubtype
}
