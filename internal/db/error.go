package db

import (
	"errors"
	"strings"

	"github.com/lib/pq"
)

// Errors returned from this package may be tested against these errors
// with errors.Is.
var (
	// ErrInvalidPublicId indicates an invalid PublicId.
	ErrInvalidPublicId = NewError(WithErrorMsg("invalid publicId"), WithErrCode(ErrCodeInvalidParameter))

	// ErrInvalidParameter is returned by create and update methods if
	// an attribute on a struct contains illegal or invalid values.
	ErrInvalidParameter = NewError(WithErrorMsg("invalid parameter"), WithErrCode(ErrCodeInvalidParameter))

	// ErrInvalidFieldMask is returned by update methods if the field mask
	// contains unknown fields or fields that cannot be updated.
	ErrInvalidFieldMask = NewError(WithErrorMsg("invalid field mask"), WithErrCode(ErrCodeInvalidParameter))

	// ErrEmptyFieldMask is returned by update methods if the field mask is
	// empty.
	ErrEmptyFieldMask = NewError(WithErrorMsg("empty field mask"), WithErrCode(ErrCodeInvalidParameter))

	// ErrNotUnique is returned by create and update methods when a write
	// to the repository resulted in a unique constraint violation.
	ErrNotUnique = NewError(WithErrorMsg("unique constraint violation"), WithErrCode(ErrCodeUnique))

	// ErrRecordNotFound returns a "record not found" error and it only occurs
	// when attempting to read from the database into struct.
	// When reading into a slice it won't return this error.
	ErrRecordNotFound = NewError(WithErrorMsg("record not found"), WithErrCode(ErrCodeRecordNotFound))

	// ErrMultipleRecords is returned by update and delete methods when a
	// write to the repository would result in more than one record being
	// changed resulting in the transaction being rolled back.
	ErrMultipleRecords = NewError(WithErrorMsg("multiple records"), WithErrCode(ErrCodeMultipleRecords))
)

// IsUniqueError returns a boolean indicating whether the error is known to
// report a unique constraint violation.
func IsUniqueError(err error) bool {
	if err == nil {
		return false
	}

	var dbError *Error
	if errors.As(err, &dbError) {
		if dbError.Code != nil && *dbError.Code == ErrCodeUnique {
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
		if dbError.Code != nil && *dbError.Code == ErrCodeCheckConstraint {
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
		if dbError.Code != nil && *dbError.Code == ErrCodeNotNull {
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
	Code    *ErrCode
	Wrapped error
}

// NewError creates a new Error and supports the options of:
// WithErrorMsg() - allows you to specify an error msg.  If a msg is specified,
// then the error class and code will be surpressed when the Error() is called.
// WithErrorCode() - allows you to specify an error code.  If no msg is
// specified, then the error class and code are used when Error() is called.
// WithWrap() - allows you to specify an error to wrap
func NewError(opt ...Option) error {
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
			msgs = append(msgs, info.Message, info.Class.String())
		}
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

// ErrClass specifies the class of error (unknown, parameter, integrity, etc).
type ErrClass uint32

// ErrCode specifies a code for the error.
type ErrCode uint32
type ErrInfo struct {
	Class   ErrClass
	Message string
}

const (
	UnknownErrClass ErrClass = 0
	ParameterError  ErrClass = 1
	IntegrityError  ErrClass = 2
	SearchError     ErrClass = 3
)

func (e ErrClass) String() string {
	return [...]string{
		"unknown",
		"parameter violation",
		"integrity violation",
		"search issue",
	}[e]
}

const (
	ErrCodeInvalidParameter ErrCode = 100
	ErrCodeCheckConstraint  ErrCode = 1000
	ErrCodeNotNull          ErrCode = 1001
	ErrCodeUnique           ErrCode = 1002
	ErrCodeRecordNotFound   ErrCode = 1100
	ErrCodeMultipleRecords  ErrCode = 1101
)

func (e ErrCode) String() string {
	if i, ok := errorCodeInfo[e]; ok {
		return i.Message
	}
	return "unknown"
}

var errorCodeInfo = map[ErrCode]ErrInfo{
	ErrCodeInvalidParameter: {
		Message: "invalid parameter",
		Class:   ParameterError,
	},
	ErrCodeCheckConstraint: {
		Message: "constraint check failed",
		Class:   IntegrityError,
	},
	ErrCodeNotNull: {
		Message: "must not be empty (null) violation",
		Class:   IntegrityError,
	},
	ErrCodeUnique: {
		Message: "must be unique violation",
		Class:   IntegrityError,
	},
	ErrCodeRecordNotFound: {
		Message: "record not fouind",
		Class:   SearchError,
	},
	ErrCodeMultipleRecords: {
		Message: "multiple records",
		Class:   SearchError,
	},
}
