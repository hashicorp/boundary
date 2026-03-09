// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

// Direction identifies the directionality of the data captured
// in the chunk.
type Direction uint8

// Directions
const (
	UnknownDirection Direction = iota
	Inbound
	Outbound
)

func (d Direction) String() string {
	switch d {
	case Inbound:
		return "inbound"
	case Outbound:
		return "outbound"
	default:
		return "unknown direction"
	}
}

// ValidDirection checks if a given Direction is valid.
func ValidDirection(d Direction) bool {
	switch d {
	case Inbound, Outbound:
		return true
	}
	return false
}
