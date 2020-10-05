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
	ErrInvalidPublicId = errors.New("invalid publicId")

	// ErrInvalidParameter is returned by create and update methods if
	// an attribute on a struct contains illegal or invalid values.
	ErrInvalidParameter = NewError(WithErrorMsg("invalid parameter"))

	// ErrInvalidFieldMask is returned by update methods if the field mask
	// contains unknown fields or fields that cannot be updated.
	ErrInvalidFieldMask = errors.New("invalid field mask")

	// ErrEmptyFieldMask is returned by update methods if the field mask is
	// empty.
	ErrEmptyFieldMask = errors.New("empty field mask")

	// ErrNotUnique is returned by create and update methods when a write
	// to the repository resulted in a unique constraint violation.
	ErrNotUnique = errors.New("unique constraint violation")

	// ErrRecordNotFound returns a "record not found" error and it only occurs
	// when attempting to read from the database into struct.
	// When reading into a slice it won't return this error.
	ErrRecordNotFound = errors.New("record not found")

	// ErrMultipleRecords is returned by update and delete methods when a
	// write to the repository would result in more than one record being
	// changed resulting in the transaction being rolled back.
	ErrMultipleRecords = errors.New("multiple records")
)

// IsUniqueError returns a boolean indicating whether the error is known to
// report a unique constraint violation.
func IsUniqueError(err error) bool {
	if err == nil {
		return false
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
// 	WithErrorCode() - allows you to specify an error code
// 	WithWrap() - allows you to specify an error to wrap
// 	WithErrorMsg() - allows you to specify an error msg
func NewError(opt ...Option) error {
	opts := GetOpts(opt...)
	if opts.withErrMsg == "" && opts.withErrCode == nil {
		opts.withErrMsg = "unknown error"

	}
	return &Error{
		Wrapped: opts.withErr,
		Msg:     opts.withErrMsg,
		Code:    opts.withErrCode,
	}
}

// Error satisfies the error interface and returns a string representation of
// the error.
func (e *Error) Error() string {
	var msgs []string
	if e.Msg != "" {
		msgs = append(msgs, e.Msg)
	}
	if e.Code != nil {
		if info, ok := errorCodeInfo[*e.Code]; ok {
			msgs = append(msgs, info.Message, info.Class.String())
		}
	}
	if len(msgs) == 0 {
		msgs = append(msgs, "unknown")
	}
	return strings.Join(msgs, ":")
}

// Unwrap implements the errors.Unwrap interface and allows callers to use the
// errors.Is() and errors.As() functions effectively for any wrapped errors.
func (e *Error) Unwrap(err error) error {
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
)

func (e ErrClass) String() string {
	return [...]string{
		"unknown",
		"parameter violation",
		"integrity violation",
	}[e]
}

const (
	ErrCodeInvalidParameter ErrCode = 100
	ErrCodeCheckConstraint  ErrCode = 1000
	ErrCodeNotNull          ErrCode = 1100
	ErrCodeUnique           ErrCode = 1200
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
}
