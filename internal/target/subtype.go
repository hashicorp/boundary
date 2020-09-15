package target

import (
	"strings"
)

type SubType int

const (
	UnknownSubtype SubType = iota
	TcpSubType
)

func (t SubType) String() string {
	switch t {
	case TcpSubType:
		return "tcp"
	}
	return "unknown"
}

// SubtypeFromType converts a string to a SubType.
// returns UnknownSubtype if no SubType with that name is found.
func SubtypeFromType(t string) SubType {
	switch {
	case strings.EqualFold(strings.TrimSpace(t), TcpSubType.String()):
		return TcpSubType
	}
	return UnknownSubtype
}

// SubtypeFromId takes any public id in the target subsystem and uses the prefix to determine
// what subtype the id is for.
// Returns UnknownSubtype if no SubType with this id's prefix is found.
func SubtypeFromId(id string) SubType {
	switch {
	case strings.HasPrefix(strings.TrimSpace(id), TcpTargetPrefix):
		return TcpSubType
	}
	return UnknownSubtype
}
