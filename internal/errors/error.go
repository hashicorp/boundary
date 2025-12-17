// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package errors

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/hashicorp/boundary/internal/event"
	pberrors "github.com/hashicorp/boundary/internal/gen/errors"
	"github.com/jackc/pgx/v5/pgconn"
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

	// Op represents the operation raising/propagating an error and is optional.
	// Op should be formatted as "package.func" for functions, while methods should
	// include the receiver type in parentheses "package.(type).func"
	Op Op

	// Wrapped is the error which this Err wraps and will be nil if there's no
	// error to wrap.
	Wrapped error
}

// E creates a new Err with provided code and supports the options of:
//
// * WithoutEvent - allows you to specify that an error event should not be
// emitted.
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
func E(ctx context.Context, opt ...Option) error {
	// nil ctx is allowed and tested for in unit tests
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

	err = &Err{
		Code:    code,
		Op:      opts.withOp,
		Wrapped: opts.withErrWrapped,
		Msg:     fmt.Sprintf(opts.withErrMsg, opts.withErrMsgArgs...),
	}
	if opts.withoutEvent {
		return err
	}

	{
		// events require an Op, but we don't want to change the error specified
		// by the caller.  So we'll build a new event and conditionally set a
		// reasonable Op based on the call stack.
		eventErr := &Err{
			Code:    err.Code,
			Op:      err.Op,
			Wrapped: err.Wrapped,
			Msg:     err.Msg,
		}
		if eventErr.Op == "" {
			const has = "github.com/hashicorp/boundary/internal/errors."
			const trim = "github.com/hashicorp/boundary/"
			for i := 0; i < 5; i++ {
				pc, _, _, ok := runtime.Caller(i)
				details := runtime.FuncForPC(pc)
				if ok && details != nil {
					if strings.HasPrefix(details.Name(), has) {
						continue
					}
					eventErr.Op = Op(strings.TrimPrefix(details.Name(), trim))
					break
				}
			}
			if eventErr.Op == "" {
				eventErr.Op = "unknown operation"
			}
		}
		event.WriteError(ctx, event.Op(eventErr.Op), eventErr)
	}

	return err
}

// New creates a new Err with provided code, op and msg
// It supports the options of:
//
// * WithWrap() - allows you to specify an error to wrap
func New(ctx context.Context, c Code, op Op, msg string, opt ...Option) error {
	if c != Unknown {
		opt = append(opt, WithCode(c))
	}
	if op != "" {
		opt = append(opt, WithOp(op))
	}
	if msg != "" {
		opt = append(opt, WithMsg(msg))
	}
	return E(ctx, opt...)
}

// Wrap creates a new Err from the provided err and op,
// preserving the code from the originating error.
// It supports the options of:
//
// * WithMsg() - allows you to specify an optional error msg, if the default
// msg for the error Code is not sufficient.
func Wrap(ctx context.Context, e error, op Op, opt ...Option) error {
	if op != "" {
		opt = append(opt, WithOp(op))
	}
	if e != nil {
		// TODO: once db package has been refactored to only return domain errors,
		// this convert can be removed
		err := Convert(e)
		if err != nil {
			// wrap the converted error
			e = err
		}
		opt = append(opt, WithWrap(e))
	}

	return E(ctx, opt...)
}

// Convert will convert the error to a Boundary *Err (returning it as an error)
// and attempt to add a helpful error msg as well. If that's not possible, it
// will return nil
func Convert(e error) *Err {
	ctx := context.TODO()
	if e == nil {
		return nil
	}
	// TODO instead of casting the error here, we should do an As.
	// Currently doing an As loses any additional context added by non-refactored packages
	// that are still wrapping with stdlib
	if err, ok := e.(*Err); ok {
		return err
	}
	var pgxError *pgconn.PgError
	if As(e, &pgxError) {
		if pgxError.Code[0:2] == "23" { // class of integrity constraint violations
			switch pgxError.Code {
			case "23505": // unique_violation
				return E(ctx, WithoutEvent(), WithMsg(pgxError.Message), WithWrap(E(ctx, WithoutEvent(), WithCode(NotUnique), WithMsg("unique constraint violation")))).(*Err)
			case "23502": // not_null_violation
				msg := fmt.Sprintf("%s must not be empty", pgxError.ColumnName)
				return E(ctx, WithoutEvent(), WithMsg(msg), WithWrap(E(ctx, WithoutEvent(), WithCode(NotNull), WithMsg("not null constraint violated")))).(*Err)
			case "23514": // check_violation
				msg := fmt.Sprintf("%s constraint failed", pgxError.ConstraintName)
				return E(ctx, WithoutEvent(), WithMsg(msg), WithWrap(E(ctx, WithoutEvent(), WithCode(CheckConstraint), WithMsg("check constraint violated")))).(*Err)
			case "23602": // set_once_column
				msg := fmt.Sprintf("%s.%s can only be set once", pgxError.TableName, pgxError.ColumnName)
				return E(ctx, WithoutEvent(), WithMsg(msg), WithWrap(E(ctx, WithoutEvent(), WithCode(ImmutableColumn), WithMsg("set_once_column constraint violated")))).(*Err)
			default:
				return E(ctx, WithoutEvent(), WithCode(NotSpecificIntegrity), WithMsg(pgxError.Message)).(*Err)
			}
		}
		switch pgxError.Code {
		case "42P01":
			return E(ctx, WithoutEvent(), WithCode(MissingTable), WithMsg(pgxError.Message), WithWrap(e)).(*Err)
		case "42703":
			return E(ctx, WithoutEvent(), WithCode(ColumnNotFound), WithMsg(pgxError.Message)).(*Err)
		case "P0001":
			return E(ctx, WithoutEvent(), WithCode(Exception), WithMsg(pgxError.Message)).(*Err)
		case "22P02":
			return E(ctx, WithoutEvent(), WithCode(InvalidTextRepresentation), WithMsg(pgxError.Message)).(*Err)

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

// ToPbErrors will convert to an Err protobuf
func ToPbErrors(err *Err) *pberrors.Err {
	pbErr := &pberrors.Err{
		Code: uint32(err.Code),
		Msg:  err.Msg,
		Op:   string(err.Op),
	}

	var wrappedErr *Err
	isWrappedErr := As(err.Wrapped, &wrappedErr)
	switch {
	case err.Wrapped == nil:
		pbErr.Wrapped = &pberrors.Err_None{
			None: false,
		}
	case isWrappedErr:
		pbErr.Wrapped = &pberrors.Err_Err{
			Err: ToPbErrors(wrappedErr),
		}
	default:
		pbErr.Wrapped = &pberrors.Err_StdError{
			StdError: err.Wrapped.Error(),
		}
	}
	return pbErr
}

// FromPbErrors will convert from Err protobuf
func FromPbErrors(pbErr *pberrors.Err) *Err {
	err := &Err{
		Code: Code(pbErr.Code),
		Msg:  pbErr.Msg,
		Op:   Op(pbErr.Op),
	}
	switch w := pbErr.Wrapped.(type) {
	case *pberrors.Err_Err:
		err.Wrapped = FromPbErrors(w.Err)
	case *pberrors.Err_StdError:
		err.Wrapped = errors.New(w.StdError)
	}
	return err
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
func As(err error, target any) bool {
	return errors.As(err, target)
}
