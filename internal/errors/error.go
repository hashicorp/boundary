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

// Err provides the ability to specify a Msg, Op, Code and Wrapped error.
// We've chosen Err over Error for the identifier to support the easy embedding of Errs.
// Errs can be embedded without a conflict between the embedded Err and Err.Error().
type Err struct {
	// Code is the error's code, which can be used to get the error's
	// errorCodeInfo, which contains the error's Kind and Message
	Code Code

	// Msg for the error
	Msg string

	// Op represents the operation raising/propagating an error and is optional
	Op Op

	// Wrapped is the error which this Err wraps and will be nil if there's no
	// error to wrap.
	Wrapped error
}

// E creates a new Err with provided code and supports the options of:
//
// * WithOp() - allows you to specify an optional Op (operation).
//
// * WithMsg() - allows you to specify an optional error msg, if the default
// msg for the error Code is not sufficient.
//
// * WithWrap() - allows you to specify an error to wrap.
// If the wrapped error is a boundary domain error, the wrapped error code
// will be used as the returned error's code.
//
// * WithCode() - allows you to specify an optional Code, this code will be prioritized
// over a code used from WithWrap().
func E(opt ...Option) error {
	opts := GetOpts(opt...)
	var code Code

	// check if options includes a wrapped error to take code from
	var err *Err
	if As(opts.withErrWrapped, &err) {
		code = err.Code
	}

	// if options include withCode prioritize using that code
	// even if one was set via wrapped error above
	if opts.withCode != Unknown {
		code = opts.withCode
	}

	return &Err{
		Code:    code,
		Op:      opts.withOp,
		Wrapped: opts.withErrWrapped,
		Msg:     opts.withErrMsg,
	}
}

// New creates a new Err with provided code, op and msg
// It supports the options of:
//
// * WithWrap() - allows you to specify an error to wrap
func New(c Code, op Op, msg string, opt ...Option) error {
	if c != Unknown {
		opt = append(opt, WithCode(c))
	}
	if op != "" {
		opt = append(opt, WithOp(op))
	}
	if msg != "" {
		opt = append(opt, WithMsg(msg))
	}

	return E(opt...)
}

// Wrap creates a new Err from the provided err and op,
// preserving the code from the originating error.
// It supports the options of:
//
// * WithMsg() - allows you to specify an optional error msg, if the default
// msg for the error Code is not sufficient.
func Wrap(e error, op Op, opt ...Option) error {
	if op != "" {
		opt = append(opt, WithOp(op))
	}
	if e != nil {
		// TODO: once db package has been refactored to only return domain errors,
		// this convert can be removed
		err := Convert(e)
		if err != nil {
			// wrapped converted error
			e = err
		}
		opt = append(opt, WithWrap(e))
	}

	return E(opt...)
}

// Convert will convert the error to a Boundary *Err (returning it as an error)
// and attempt to add a helpful error msg as well. If that's not possible, it
// will return nil
func Convert(e error) *Err {
	if e == nil {
		return nil
	}
	var err *Err
	if As(e, &err) {
		return err
	}
	var pqError *pq.Error
	if As(e, &pqError) {
		if pqError.Code.Class() == "23" { // class of integrity constraint violations
			switch pqError.Code {
			case "23505": // unique_violation
				return E(WithMsg(pqError.Detail), WithWrap(ErrNotUnique)).(*Err)
			case "23502": // not_null_violation
				msg := fmt.Sprintf("%s must not be empty", pqError.Column)
				return E(WithMsg(msg), WithWrap(ErrNotNull)).(*Err)
			case "23514": // check_violation
				msg := fmt.Sprintf("%s constraint failed", pqError.Constraint)
				return E(WithMsg(msg), WithWrap(ErrCheckConstraint)).(*Err)
			default:
				return E(WithCode(NotSpecificIntegrity), WithMsg(pqError.Message)).(*Err)
			}
		}
		if pqError.Code == "42P01" {
			return E(WithCode(MissingTable), WithMsg(pqError.Message)).(*Err)
		}
	}
	// unfortunately, we can't help.
	return nil
}

// Info about the Err
func (e *Err) Info() Info {
	if e == nil {
		return errorCodeInfo[Unknown]
	}
	return e.Code.Info()
}

// Error satisfies the error interface and returns a string representation of
// the Err
func (e *Err) Error() string {
	if e == nil {
		return ""
	}
	var s strings.Builder
	if e.Op != "" {
		join(&s, ": ", string(e.Op))
	}
	if e.Msg != "" {
		join(&s, ": ", e.Msg)
	}

	var skipInfo bool
	var wrapped *Err
	if As(e.Wrapped, &wrapped) {
		// if wrapped error code is the same as this error, don't print redundant info
		skipInfo = wrapped.Code == e.Code
	}

	if info, ok := errorCodeInfo[e.Code]; ok && !skipInfo {
		if e.Msg == "" {
			join(&s, ": ", info.Message) // provide a default.
			join(&s, ", ", info.Kind.String())
		} else {
			join(&s, ": ", info.Kind.String())
		}
		join(&s, ": ", fmt.Sprintf("error #%d", e.Code))
	}

	if e.Wrapped != nil {
		join(&s, ": ", e.Wrapped.Error())
	}
	return s.String()
}

func join(str *strings.Builder, delim string, s string) {
	if str.Len() == 0 {
		_, _ = str.WriteString(s)
		return
	}
	_, _ = str.WriteString(delim + s)
}

// Unwrap implements the errors.Unwrap interface and allows callers to use the
// errors.Is() and errors.As() functions effectively for any wrapped errors.
func (e *Err) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Wrapped
}

// Is the equivalent of the std errors.Is, but allows Devs to only import
// this package for the capability.
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As is the equivalent of the std errors.As, and allows devs to only import
// this package for the capability.
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}
