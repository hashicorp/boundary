package errors

import (
	"errors"

	"github.com/lib/pq"
)

// IsUniqueError returns a boolean indicating whether the error is known to
// report a unique constraint violation.
func IsUniqueError(err error) bool {
	if err == nil {
		return false
	}

	var domainErr *Err
	if errors.As(err, &domainErr) {
		if domainErr.Code == NotUnique {
			return true
		}
	}

	var pqError *pq.Error
	if errors.As(err, &pqError) {
		if pqError.Code == "23505" { // unique_violation
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

	var domainErr *Err
	if errors.As(err, &domainErr) {
		if domainErr.Code == CheckConstraint {
			return true
		}
	}

	var pqError *pq.Error
	if errors.As(err, &pqError) {
		if pqError.Code == "23514" { // check_violation
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

	var domainErr *Err
	if errors.As(err, &domainErr) {
		if domainErr.Code == NotNull {
			return true
		}
	}

	var pqError *pq.Error
	if errors.As(err, &pqError) {
		if pqError.Code == "23502" { // not_null_violation
			return true
		}
	}

	return false
}

// IsMissingTableError returns a boolean indicating whether the error is known
// to report a undefined/missing table violation.
func IsMissingTableError(err error) bool {
	var pqError *pq.Error
	if errors.As(err, &pqError) {
		if pqError.Code == "42P01" {
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

	var domainErr *Err
	if errors.As(err, &domainErr) {
		if domainErr.Code == RecordNotFound {
			return true
		}
	}

	return false
}
