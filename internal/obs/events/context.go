package event

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
)

type key int

var eventerKey key
var requestInfoKey key

type RequestInfo struct {
	ID string
}

func NewEventerContext(ctx context.Context, eventer *Eventer) (context.Context, error) {
	return context.WithValue(ctx, eventerKey, eventer), nil
}

func WriteInfo(ctx context.Context, caller Op, opt ...Option) error {
	const op = "event.Info"
	opts := getOpts(opt...)
	if opts.withDetails == nil && opts.withHeader == nil {
		return errors.New(errors.InvalidParameter, op, "you must specify either header or details options for an event payload")
	}
	eventer, ok := ctx.Value(eventerKey).(*Eventer)
	if !ok {
		return errors.New(errors.InvalidParameter, op, "context missing eventer")
	}
	reqInfo, ok := ctx.Value(requestInfoKey).(*RequestInfo)
	if !ok {
		return errors.New(errors.InvalidParameter, op, "context missing request info")
	}
	e, err := NewInfo(Id(reqInfo.ID), caller, opt...)
	if err != nil {
		return errors.Wrap(err, op)
	}
	if err := eventer.Info(ctx, e, opt...); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}
