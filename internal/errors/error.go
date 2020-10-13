package errors

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

// IsUniqueError returns a boolean indicating whether the error is known to
// report a unique constraint violation.
func IsUniqueError(err error) bool {
	if err == nil {
		return false
	}

	var domainErr *Error
	if errors.As(err, &domainErr) {
		if domainErr.Code == NotUnique {
			return true
		}
	}

	var pqError *pq.Error
	if errors.As(err, &pqError) {
		if pqError.Code.Name() == "unique_violation" {
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

	var domainErr *Error
	if errors.As(err, &domainErr) {
		if domainErr.Code == CheckConstraint {
			return true
		}
	}

	var pqError *pq.Error
	if errors.As(err, &pqError) {
		if pqError.Code.Name() == "check_violation" {
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

	var domainErr *Error
	if errors.As(err, &domainErr) {
		if domainErr.Code == NotNull {
			return true
		}
	}

	var pqError *pq.Error
	if errors.As(err, &pqError) {
		if pqError.Code.Name() == "not_null_violation" {
			return true
		}
	}

	return false
}

// Op represents an operation (package.function).
// For example iam.CreateRole
type Op string

// Error provides the ability to specify a Msg, Op, Code and Wrapped error.
// Errors must have a Code and all other fields are optional.
type Error struct {
	// Code is the error's code, which can be used to get the error's
	// errorCodeInfo, which contains the error's Kind and Message
	Code Code

	// Msg for the error
	Msg string

	// Op represents the operation raising/propagating an error and is optional
	Op Op

	// Wrapped is the error which this Error wraps and will be nil if there's no
	// error to wrap.
	Wrapped error
}

// New creates a new Error and supports the options of:
// WithErrorMsg() - allows you to specify an optional error msg, if the default
// msg for the error Code is not sufficient. WithWrap() - allows you to specify
// an error to wrap
func New(c Code, opt ...Option) error {
	opts := GetOpts(opt...)
	return &Error{
		Code:    c,
		Wrapped: opts.withErrWrapped,
		Msg:     opts.withErrMsg,
	}
}

// Convert will convert the error to Error (if that's not possible, it just
// returns the error as is) and it will attempt to add a helpful error msg too.
func Convert(e error) error {
	// nothing to convert.
	if e == nil {
		return nil
	}

	var alreadyConverted *Error
	if errors.As(e, &alreadyConverted) {
		return alreadyConverted
	}

	var pqError *pq.Error
	if errors.As(e, &pqError) {
		if pqError.Code.Name() == "unique_violation" {
			return New(NotUnique, WithErrorMsg(pqError.Detail), WithWrap(ErrNotUnique))
		}
		if pqError.Code.Name() == "not_null_violation" {
			msg := fmt.Sprintf("%s must not be empty", pqError.Column)
			return New(NotNull, WithErrorMsg(msg), WithWrap(ErrNotNull))
		}
		if pqError.Code.Name() == "check_violation" {
			msg := fmt.Sprintf("%s constraint failed", pqError.Constraint)
			return New(CheckConstraint, WithErrorMsg(msg), WithWrap(ErrCheckConstraint))
		}
	}
	// unfortunately, we can't help.
	return e
}

// Error satisfies the error interface and returns a string representation of
// the error.
func (e *Error) Error() string {
	var msgs []string
	// try to use the error msg first...
	if e.Msg != "" {
		msgs = append(msgs, e.Msg)
	}
	if info, ok := errorCodeInfo[e.Code]; ok {
		msgs = append(msgs, info.Message, info.Kind.String())
	}
	msgs = append(msgs, fmt.Sprintf("error #%d", e.Code))

	return strings.Join(msgs, ": ")
}

// Unwrap implements the errors.Unwrap interface and allows callers to use the
// errors.Is() and errors.As() functions effectively for any wrapped errors.
func (e *Error) Unwrap() error {
	return e.Wrapped
}
