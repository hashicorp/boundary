// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import "regexp"

// Protocol identifies the protocol of the data captured in a chunk.
type Protocol string

// ValidProtocol checks if a given Protocol is valid.
func ValidProtocol(p Protocol) bool {
	return len(p) <= protocolSize
}

// ToText converts a protocol to a text-safe string
func (p Protocol) ToText() string {
	re := regexp.MustCompile("[[:^ascii:]]")
	t := re.ReplaceAllLiteralString(string(p), "")
	return t
}
