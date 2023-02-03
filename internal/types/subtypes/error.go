// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package subtypes

// UnknownSubtypeIDError is an error type that describes an invalid
// resource sub-type identifer. For example, this authentication sub-type
// ID "ampwd_1234567890" is an error because the prefix "ampwd" is invalid.
type UnknownSubtypeIDError struct {
	// ID is the resource identifier
	ID string
}

// Error returns a string describing an unknown subtype based on a given resource ID
// Example: "unknown subtype in ID: ampwd_1234567890"
func (e *UnknownSubtypeIDError) Error() string {
	return "unknown subtype in ID: " + e.ID
}
