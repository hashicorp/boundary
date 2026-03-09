// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"fmt"
)

// FilterOperation defines a filter operation (none, redact, encrypt, etc)
type FilterOperation string

const (
	NoOperation         FilterOperation = ""            // NoOperation specifies no operation.
	UnknownOperation    FilterOperation = "unknown"     // UnknownOperation specifies an unknown operation.
	RedactOperation     FilterOperation = "redact"      // RedactOperation specifies an redaction operation
	EncryptOperation    FilterOperation = "encrypt"     // EncryptOperation specifies an encryption operation.
	HmacSha256Operation FilterOperation = "hmac-sha256" // HmacSha256Operation specifies an hmac-sha256 operation
)

// Validate the FilterOperation
func (fop FilterOperation) Validate() error {
	const op = "event.(DataClassification).Validate"
	switch fop {
	case RedactOperation, EncryptOperation, HmacSha256Operation, NoOperation:
		return nil
	default:
		return fmt.Errorf("%s: invalid filter operation '%s': %w", op, fop, ErrInvalidParameter)
	}
}

// AuditFilterOperation defines a map between DataClassifications and
// FilterOperations for audit filtering
type AuditFilterOperations map[DataClassification]FilterOperation

// Validate the AuditFilterOperation
func (af AuditFilterOperations) Validate() error {
	const op = "event.(AuditFilterOperations).Validate"
	for k, v := range af {
		if err := k.Validate(); err != nil {
			return fmt.Errorf("%s: invalid filter override classification (%s): %w", op, k, err)
		}
		if err := v.Validate(); err != nil {
			return fmt.Errorf("%s: invalid filter override operation (%s): %w", op, v, err)
		}
	}
	return nil
}

// DefaultAuditFilterOperations will return a map of the default
// AuditConfig.AuditFilters
func DefaultAuditFilterOperations() AuditFilterOperations {
	const op = "event.DefaultAuditFilterOperations"
	return AuditFilterOperations{
		SensitiveClassification: RedactOperation,
		SecretClassification:    RedactOperation,
	}
}
