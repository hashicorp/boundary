// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package errors

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// IsUniqueError returns a boolean indicating whether the error is known to
// report a unique constraint violation.
func IsUniqueError(err error) bool {
	if err == nil {
		return false
	}

	if Match(T(NotUnique), err) {
		return true
	}

	var pgxError *pgconn.PgError
	if errors.As(err, &pgxError) {
		if pgxError.Code == "23505" { // unique_violation
			return true
		}
	}

	return false
}

// IsCheckConstraintError returns a boolean indicating whether the error is
// known to report a check constraint violation.
func IsCheckConstraintError(err error) bool {
	if err == nil {
		return false
	}

	if Match(T(CheckConstraint), err) {
		return true
	}

	var pgxError *pgconn.PgError
	if errors.As(err, &pgxError) {
		if pgxError.Code == "23514" { // check_violation
			return true
		}
	}

	return false
}

// IsNotNullError returns a boolean indicating whether the error is known
// to report a not-null constraint violation.
func IsNotNullError(err error) bool {
	if err == nil {
		return false
	}

	if Match(T(NotNull), err) {
		return true
	}

	var pgxError *pgconn.PgError
	if errors.As(err, &pgxError) {
		if pgxError.Code == "23502" { // not_null_violation
			return true
		}
	}

	return false
}

// IsMissingTableError returns a boolean indicating whether the error is known
// to report a undefined/missing table violation.
func IsMissingTableError(err error) bool {
	var pgxError *pgconn.PgError
	if errors.As(err, &pgxError) {
		if pgxError.Code == "42P01" {
			return true
		}
	}
	return false
}

// IsNotFoundError returns a boolean indicating whether the error is known to
// report a not found violation.
func IsNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	if Match(T(RecordNotFound), err) {
		return true
	}

	return false
}

// IsConflictError returns a boolean indicating whether the error is known to
// report a pre-conditional check violation or an aborted transaction.
func IsConflictError(err error) bool {
	if err == nil {
		return false
	}

	return Match(T(Conflict), err)
}
