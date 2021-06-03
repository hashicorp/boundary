package event

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-hclog"
)

type key int

const (
	eventerKey key = iota
	requestInfoKey
)

// NewEventerContext will return a context containing a value of the provided Eventer
func NewEventerContext(ctx context.Context, eventer *Eventer) (context.Context, error) {
	const op = "event.NewEventerContext"
	if ctx == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing context")
	}
	if eventer == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing eventer")
	}
	return context.WithValue(ctx, eventerKey, eventer), nil
}

// EventerFromContext attempts to get the eventer value from the context provided
func EventerFromContext(ctx context.Context) (*Eventer, bool) {
	const op = "event.EventerFromContext"
	if ctx == nil {
		return nil, false
	}
	eventer, ok := ctx.Value(eventerKey).(*Eventer)
	return eventer, ok
}

// NewRequestInfoContext will return a context containing a value for the
// provided RequestInfo
func NewRequestInfoContext(ctx context.Context, info *RequestInfo) (context.Context, error) {
	const op = "event.NewRequestInfoContext"
	if ctx == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing context")
	}
	if info == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing request info")
	}
	if info.Id == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing request info id")
	}
	return context.WithValue(ctx, requestInfoKey, info), nil
}

// RequestInfoFromContext attempts to get the RequestInfo value from the context
// provided
func RequestInfoFromContext(ctx context.Context) (*RequestInfo, bool) {
	const op = "event.RequestInfoFromContext"
	if ctx == nil {
		return nil, false
	}
	reqInfo, ok := ctx.Value(requestInfoKey).(*RequestInfo)
	return reqInfo, ok
}

// WriteObservation will write an observation event.  It will first check the
// ctx for an eventer, then try event.SysEventer() and if no eventer can be
// found an error is returned.
//
// At least one and any combination of the supported options may be used:
// WithHeader, WithDetails, WithId, WithFlush and WithRequestInfo. All other
// options are ignored.
func WriteObservation(ctx context.Context, caller Op, opt ...Option) error {
	const op = "event.WriteObservation"
	eventer, ok := EventerFromContext(ctx)
	if !ok {
		eventer = SysEventer()
		if eventer == nil {
			return errors.New(errors.InvalidParameter, op, "missing both context and system eventer")
		}
	}
	opts := getOpts(opt...)
	if opts.withDetails == nil && opts.withHeader == nil && !opts.withFlush {
		return errors.New(errors.InvalidParameter, op, "you must specify either header or details options for an event payload")
	}
	if opts.withRequestInfo == nil {
		var err error
		if opt, err = addCtxOptions(ctx, opt...); err != nil {
			return errors.Wrap(err, op)
		}
	}
	e, err := newObservation(caller, opt...)
	if err != nil {
		return errors.Wrap(err, op)
	}
	if err := eventer.writeObservation(ctx, e); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

// WriteError will write an error event.  It will first check the
// ctx for an eventer, then try event.SysEventer() and if no eventer can be
// found an hclog.Logger will be created and used.
//
// The options WithId and WithRequestInfo are supported and all other options
// are ignored.
func WriteError(ctx context.Context, caller Op, e error, opt ...Option) {
	const op = "event.WriteError"
	eventer, ok := EventerFromContext(ctx)
	if !ok {
		eventer = SysEventer()
		if eventer == nil {
			logger := hclog.New(nil)
			logger.Error("%s: no eventer available to write error: %w", e)
			return
		}
	}
	opts := getOpts(opt...)
	if opts.withRequestInfo == nil {
		var err error
		if opt, err = addCtxOptions(ctx, opt...); err != nil {
			eventer.logger.Error("%s: %w", errors.Wrap(err, op))
			eventer.logger.Error("%s: unable to process context options to write error: %w", e)
			return
		}
	}
	ev, err := newError(caller, e, opt...)
	if err != nil {
		eventer.logger.Error("%s: %w", errors.Wrap(err, op))
		eventer.logger.Error("%s: unable to create new error to write error: %w", e)
		return
	}
	if err := eventer.writeError(ctx, ev); err != nil {
		eventer.logger.Error("%s: %w", errors.Wrap(err, op))
		eventer.logger.Error("%s: unable to write error: %w", e)
		return
	}
}

// WriteAudit will write an audit event.  It will first check the ctx for an
// eventer, then try event.SysEventer() and if no eventer can be  found an error
// is returned.
//
// At least one and any combination of the supported options may be used:
// WithRequest, WithResponse, WithAuth, WithId, WithFlush and WithRequestInfo.
// All other options are ignored.
func WriteAudit(ctx context.Context, caller Op, opt ...Option) error {
	const op = "event.WriteAudit"
	eventer, ok := EventerFromContext(ctx)
	if !ok {
		eventer = SysEventer()
		if eventer == nil {
			return errors.New(errors.InvalidParameter, op, "missing both context and system eventer")
		}
	}
	opts := getOpts(opt...)
	if opts.withRequestInfo == nil {
		var err error
		if opt, err = addCtxOptions(ctx, opt...); err != nil {
			return errors.Wrap(err, op)
		}
	}
	e, err := newAudit(caller, opt...)
	if err != nil {
		return errors.Wrap(err, op)
	}
	if err := eventer.writeAudit(ctx, e); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

func addCtxOptions(ctx context.Context, opt ...Option) ([]Option, error) {
	const op = "event.addCtxOptions"
	opts := getOpts(opt...)
	retOpts := make([]Option, 0, len(opt))
	retOpts = append(retOpts, opt...)
	if opts.withRequestInfo == nil {
		reqInfo, ok := RequestInfoFromContext(ctx)
		if !ok {
			return nil, errors.New(errors.InvalidParameter, op, "context missing request info")
		}
		retOpts = append(retOpts, WithRequestInfo(reqInfo))
		if reqInfo.Id != "" {
			retOpts = append(retOpts, WithId(reqInfo.Id))
		}
	}
	return retOpts, nil
}
