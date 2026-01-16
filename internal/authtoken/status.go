// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtoken

// Status of the AuthToken.  It will default IssuedStatus in the database.
type Status string

const (
	// UnknownStatus for the token.
	UnknownStatus Status = "unknown"

	// PendingStatus means that the token has been created but it pending while
	// waiting to be issued.
	PendingStatus Status = "auth token pending"

	// IssuedStatus means the token has been issued.  It is a final status for the
	// token.
	IssuedStatus Status = "token issued"

	// FailedStatus means the token is in a failed status before it was issued and
	// this is a final status.
	FailedStatus Status = "authentication failed"

	// SystemErrorStatus means that the system encountered an error before
	// issuing the token. This is a final status.
	SystemErrorStatus Status = "system error"
)
