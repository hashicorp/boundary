// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sentinel

const (
	// Start is the Unicode special non-character U+FFFE, and the prefix included in all
	// Boundary defined sentinel values.
	Start = '\ufffe'

	// End is the Unicode special non-character U+FFFF, and the suffix included in all
	// Boundary defined sentinel values.
	End = '\uffff'
)

const (
	// ExternalIdNone is a Boundary sentinel indicating that no id was provided by an
	// external system.
	ExternalIdNone = "\ufffenone\uffff"
)

// Is returns true if s is a valid sentinel.
func Is(s string) bool {
	// A valid sentinel must be at least 6 bytes in length, 3 bytes for '\ufffe' and 3
	// bytes for '\uffff'.
	if len(s) < 6 {
		return false
	}
	sr := []rune(s)
	if sr[0] == Start && sr[len(sr)-1] == End {
		return true
	}
	return false
}
