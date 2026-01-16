// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import "fmt"

// DataClassification defines a data classification (public, sensitive, secret, etc)
type DataClassification string

const (
	UnknownClassification DataClassification = "unknown"

	// PublicClassification declares a field as public data.  No filter
	// operations are ever performed on public data.
	PublicClassification DataClassification = "public"

	// SensitiveClassification declares a field as sensitive data.  By default,
	// sensitive data is encrypted unless there are AuditConfig.FilterOverrides
	SensitiveClassification DataClassification = "sensitive"

	// SecretClassification declares a field as secret data.  By default,
	// secret data is redacted unless there are AuditConfig.FilterOverrides
	SecretClassification DataClassification = "secret"
)

// Validate the DataClassification
func (dc DataClassification) Validate() error {
	const op = "event.(DataClassification).Validate"
	switch dc {
	case PublicClassification, SensitiveClassification, SecretClassification:
		return nil
	default:
		return fmt.Errorf("%s: invalid data classification '%s': %w", op, dc, ErrInvalidParameter)
	}
}
