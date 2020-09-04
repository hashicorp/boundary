package auth

import (
	"strings"

	"github.com/hashicorp/boundary/internal/auth/password"
)

type SubType int

const (
	UnknownSubtype SubType = iota
	PasswordSubtype
)

func (t SubType) String() string {
	switch t {
	case PasswordSubtype:
		return "password"
	}
	return "unknown"
}

// SubtypeFromType converts a string to a SubType.
// returns UnknownSubtype if no SubType with that name is found.
func SubtypeFromType(t string) SubType {
	switch {
	case strings.EqualFold(strings.TrimSpace(t), PasswordSubtype.String()):
		return PasswordSubtype
	}
	return UnknownSubtype
}

// SubtypeFromId takes any public id in the auth subsystem and uses the prefix to determine
// what subtype the id is for.
// Returns UnknownSubtype if no SubType with this id's prefix is found.
func SubtypeFromId(id string) SubType {
	switch {
	case strings.HasPrefix(strings.TrimSpace(id), password.AuthMethodPrefix),
		strings.HasPrefix(strings.TrimSpace(id), password.AccountPrefix):
		return PasswordSubtype
	}
	return UnknownSubtype
}
