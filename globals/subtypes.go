// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package globals

// Subtype variables identify a boundary resource subtype.
type Subtype string

const (
	UnknownSubtype Subtype = "unknown"
)

// String returns the string representation of a Subtype
func (t Subtype) String() string {
	return string(t)
}
