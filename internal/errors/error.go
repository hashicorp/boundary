package errors

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

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

// Info about the Error
func (e *Error) Info() Info {
	if info, ok := errorCodeInfo[e.Code]; ok {
		return info
	}
	return errorCodeInfo[Unknown]
}

// Error satisfies the error interface and returns a string representation of
// the error.
func (e *Error) Error() string {
	var msgs []string
	if e.Op != "" {
		msgs = append(msgs, string(e.Op))
	}

	if e.Msg != "" {
		msgs = append(msgs, e.Msg)
	}

	if info, ok := errorCodeInfo[e.Code]; ok {
		if e.Msg == "" {
			// provide a default...
			msgs = append(msgs, info.Message)
		}
		msgs = append(msgs, info.Kind.String())
	}
	msgs = append(msgs, fmt.Sprintf("error #%d", e.Code))

	if e.Wrapped != nil {
		msgs = append(msgs, e.Error())
	}

	return strings.Join(msgs, ": ")
}

// Unwrap implements the errors.Unwrap interface and allows callers to use the
// errors.Is() and errors.As() functions effectively for any wrapped errors.
func (e *Error) Unwrap() error {
	return e.Wrapped
}
