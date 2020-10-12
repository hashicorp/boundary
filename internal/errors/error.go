package errors

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

// Errors returned from this package may be tested against these errors
// with errors.Is.
var (
	// ErrInvalidPublicId indicates an invalid PublicId.
	ErrInvalidPublicId = New(WithErrorMsg("invalid publicId"), WithErrCode(InvalidParameter))

	// ErrInvalidParameter is returned by create and update methods if
	// an attribute on a struct contains illegal or invalid values.
	ErrInvalidParameter = New(WithErrorMsg("invalid parameter"), WithErrCode(InvalidParameter))

	// ErrInvalidFieldMask is returned by update methods if the field mask
	// contains unknown fields or fields that cannot be updated.
	ErrInvalidFieldMask = New(WithErrorMsg("invalid field mask"), WithErrCode(InvalidParameter))

	// ErrEmptyFieldMask is returned by update methods if the field mask is
	// empty.
	ErrEmptyFieldMask = New(WithErrorMsg("empty field mask"), WithErrCode(InvalidParameter))

	// ErrNotUnique is returned by create and update methods when a write
	// to the repository resulted in a unique constraint violation.
	ErrNotUnique = New(WithErrorMsg("unique constraint violation"), WithErrCode(NotUnique))

	// ErrNotNull is returned by methods when a write to the repository resulted
	// in a check constraint violation
	ErrCheckConstraint = New(WithErrorMsg("check constraint violated"), WithErrCode(CheckConstraint))

	// ErrNotNull is returned by methods when a write to the repository resulted
	// in a not null constraint violation
	ErrNotNull = New(WithErrorMsg("not null constraint violated"), WithErrCode(NotNull))

	// ErrRecordNotFound returns a "record not found" error and it only occurs
	// when attempting to read from the database into struct.
	// When reading into a slice it won't return this error.
	ErrRecordNotFound = New(WithErrorMsg("record not found"), WithErrCode(RecordNotFound))

	// ErrMultipleRecords is returned by update and delete methods when a
	// write to the repository would result in more than one record being
	// changed resulting in the transaction being rolled back.
	ErrMultipleRecords = New(WithErrorMsg("multiple records"), WithErrCode(MultipleRecords))
)

// IsUniqueError returns a boolean indicating whether the error is known to
// report a unique constraint violation.
func IsUniqueError(err error) bool {
	if err == nil {
		return false
	}

	var dbError *Error
	if errors.As(err, &dbError) {
		if dbError.Code != nil && *dbError.Code == NotUnique {
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

	var dbError *Error
	if errors.As(err, &dbError) {
		if dbError.Code != nil && *dbError.Code == CheckConstraint {
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

	var dbError *Error
	if errors.As(err, &dbError) {
		if dbError.Code != nil && *dbError.Code == NotNull {
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

// Error provides the ability to specify a msg, code and wrapped error.
type Error struct {
	// Msg for the error
	Msg string
	// Code is the error's code
	Code    *Code
	Wrapped error
}

// New creates a new Error and supports the options of:
// WithErrorMsg() - allows you to specify an error msg.  If a msg is specified,
// then the error class and code will be surpressed when the Error() is called.
// WithErrorCode() - allows you to specify an error code.  If no msg is
// specified, then the error class and code are used when Error() is called.
// WithWrap() - allows you to specify an error to wrap
func New(opt ...Option) error {
	opts := GetOpts(opt...)
	if opts.withErrMsg == "" && opts.withErrCode == nil {
		opts.withErrMsg = "unknown error"

	}
	return &Error{
		Wrapped: opts.withErrWrapped,
		Msg:     opts.withErrMsg,
		Code:    opts.withErrCode,
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
			return New(WithErrorMsg(pqError.Detail), WithErrCode(NotUnique), WithWrap(ErrNotUnique))
		}
		if pqError.Code.Name() == "not_null_violation" {
			msg := fmt.Sprintf("%s must not be empty", pqError.Column)
			return New(WithErrorMsg(msg), WithErrCode(NotNull), WithWrap(ErrNotNull))
		}
		if pqError.Code.Name() == "check_violation" {
			msg := fmt.Sprintf("%s constraint failed", pqError.Constraint)
			return New(WithErrorMsg(msg), WithErrCode(CheckConstraint), WithWrap(ErrCheckConstraint))
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

	// since there's no err msg, let's try the err class/code...
	if e.Msg == "" && e.Code != nil {
		if info, ok := errorCodeInfo[*e.Code]; ok {
			msgs = append(msgs, info.Message, info.Kind.String())
		}
	}
	if e.Code != nil {
		msgs = append(msgs, fmt.Sprintf("error #%d", *e.Code))
	}

	// if there's still nada, how about the wrapped error...
	if len(msgs) == 0 && e.Wrapped != nil {
		msgs = append(msgs, e.Wrapped.Error())
	}

	// okay, we have to output something...
	if len(msgs) == 0 {
		msgs = append(msgs, "unknown")
	}
	return strings.Join(msgs, ": ")
}

// Unwrap implements the errors.Unwrap interface and allows callers to use the
// errors.Is() and errors.As() functions effectively for any wrapped errors.
func (e *Error) Unwrap() error {
	return e.Wrapped
}
