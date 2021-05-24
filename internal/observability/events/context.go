package event

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
)

type key int

const (
	EventerKey key = iota
	RequestInfoKey
)

func NewEventerContext(ctx context.Context, eventer *Eventer) (context.Context, error) {
	const op = "event.NewEventerContext"
	if ctx == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing context")
	}
	if eventer == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing eventer")
	}
	return context.WithValue(ctx, EventerKey, eventer), nil
}

func NewRequestInfoContext(ctx context.Context, info *RequestInfo) (context.Context, error) {
	const op = "event.NewRequestInfoContext"
	if ctx == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing context")
	}
	if info == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing request info")
	}
	if info.Id == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing request info ID")
	}
	return context.WithValue(ctx, RequestInfoKey, info), nil
}

func WriteObservation(ctx context.Context, caller Op, opt ...Option) error {
	const op = "event.WriteObservation"
	eventer, ok := ctx.Value(EventerKey).(*Eventer)
	if !ok {
		return errors.New(errors.InvalidParameter, op, "context missing eventer")
	}
	opts := getOpts(opt...)
	if opts.withDetails == nil && opts.withHeader == nil {
		return errors.New(errors.InvalidParameter, op, "you must specify either header or details options for an event payload")
	}
	if opts.withRequestInfo == nil {
		var err error
		if opt, err = addCtxOptions(ctx, opt...); err != nil {
			return errors.Wrap(err, op)
		}
	}
	e, err := NewObservation(caller, opt...)
	if err != nil {
		return errors.Wrap(err, op)
	}
	if err := eventer.writeObservation(ctx, e, opt...); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

func WriteError(ctx context.Context, caller Op, e error, opt ...Option) error {
	const op = "event.WriteError"
	eventer, ok := ctx.Value(EventerKey).(*Eventer)
	if !ok {
		return errors.New(errors.InvalidParameter, op, "context missing eventer")
	}
	opts := getOpts(opt...)
	if opts.withRequestInfo == nil {
		var err error
		if opt, err = addCtxOptions(ctx, opt...); err != nil {
			return errors.Wrap(err, op)
		}
	}
	ev, err := NewError(caller, e, opt...)
	if err != nil {
		return errors.Wrap(err, op)
	}
	if err := eventer.writeError(ctx, ev); err != nil {
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
		reqInfo, ok := ctx.Value(RequestInfoKey).(*RequestInfo)
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
