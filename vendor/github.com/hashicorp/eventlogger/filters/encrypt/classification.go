// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package encrypt

const (
	// RedactedData is the value that replaces redacted data (secrets)
	RedactedData = "[REDACTED]"

	// DataClassificationTagName is the tag name for classifying data into
	// DataClassification's
	DataClassificationTagName = "class"
)

// DataClassification defines a type for classification of data into categories
// like: public, sensitive, secret, etc.  DataClassifications are used with as
// values for tags using DataClassificationTagName to declare a type of
// classification.
type DataClassification string

const (
	UnknownClassification DataClassification = "unknown"

	// PublicClassification declares a field as public data.  No filter
	// operations are ever performed on public data.
	PublicClassification DataClassification = "public"

	// SensitiveClassification declares a field as sensitive data.  By default,
	// sensitive data is encrypted unless the tag includes an overriding FilterOperation.
	SensitiveClassification DataClassification = "sensitive"

	// SecretClassification declares a field as secret data.  By default,
	// secret data is redacted unless the tag includes an overriding FilterOperation.
	SecretClassification DataClassification = "secret"
)
