// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package encrypt

import "strings"

// FilterOperation defines a type for filtering operations like: redact,
// encrypt, hmac-sha256, etc.  Used in combination with a DataClassification, it
// allows developers to override the default filter operations on tag fields.
type FilterOperation string

const (
	NoOperation         FilterOperation = ""
	UnknownOperation    FilterOperation = "unknown"
	RedactOperation     FilterOperation = "redact"
	EncryptOperation    FilterOperation = "encrypt"
	HmacSha256Operation FilterOperation = "hmac-sha256"
)

func convertToOperation(seg string) FilterOperation {
	seg = strings.ToLower(seg)
	switch FilterOperation(seg) {
	case NoOperation:
		return NoOperation
	case HmacSha256Operation:
		return HmacSha256Operation
	case EncryptOperation:
		return EncryptOperation
	case RedactOperation:
		return RedactOperation
	default:
		return UnknownOperation
	}
}
