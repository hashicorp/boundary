package target

import (
	"strings"
)

type Subtype int

const (
	UnknownSubtype Subtype = iota
	TcpSubtype
)

func (t Subtype) String() string {
	switch t {
	case TcpSubtype:
		return "tcp"
	}
	return "unknown"
}

// SubtypeFromType converts a string to a Subtype.
// returns UnknownSubtype if no Subtype with that name is found.
func SubtypeFromType(t string) Subtype {
	switch {
	case strings.EqualFold(strings.TrimSpace(t), TcpSubtype.String()):
		return TcpSubtype
	}
	return UnknownSubtype
}

// SubtypeFromId takes any public id in the target subsystem and uses the prefix to determine
// what subtype the id is for.
// Returns UnknownSubtype if no Subtype with this id's prefix is found.
func SubtypeFromId(id string) Subtype {
	switch {
	case strings.HasPrefix(strings.TrimSpace(id), TcpTargetPrefix):
		return TcpSubtype
	}
	return UnknownSubtype
}
