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

type RequestInfo struct {
	Id string
}

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

func WriteInfo(ctx context.Context, caller Op, opt ...Option) error {
	const op = "event.Info"
	opts := getOpts(opt...)
	if opts.withDetails == nil && opts.withHeader == nil {
		return errors.New(errors.InvalidParameter, op, "you must specify either header or details options for an event payload")
	}
	eventer, ok := ctx.Value(EventerKey).(*Eventer)
	if !ok {
		return errors.New(errors.InvalidParameter, op, "context missing eventer")
	}
	reqInfo, ok := ctx.Value(RequestInfoKey).(*RequestInfo)
	if !ok {
		return errors.New(errors.InvalidParameter, op, "context missing request info")
	}
	e, err := NewInfo(reqInfo.Id, caller, opt...)
	if err != nil {
		return errors.Wrap(err, op)
	}
	if err := eventer.Info(ctx, e, opt...); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}
