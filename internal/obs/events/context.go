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

// RequestInfo defines the fields captured about a Boundary request.  This type
// is duplicated in the internal/auth package, but there are circular dependency
// issues.  TBD how to resolve this, but for now, we've dupped it here.
//
// fields are intentionally alphabetically ordered so they will match output
// from marshaling event json
type RequestInfo struct {
	Id       string    `json:"id,omitempty"`
	Method   string    `json:"method,omitempty"`
	Path     string    `json:"path,omitempty"`
	PublicId string    `json:"public_id,omitempty"`
	UserInfo *UserInfo `json:"user_info,omitempty"`
}

// UserInfo defines the fields captured about a user for a Boundary request.
// This type is duplicated in the internal/auth package, but there are circular
// dependency issues.  TBD how to resolve this, but for now, we've dupped it
// here.
//
// fields are intentionally alphabetically ordered so they will match output
// from marshaling event json
type UserInfo struct {
	Grants []GrantsPair `json:"grants_pair,omitempty"`
	Id     string       `json:"id,omitempty"`
}

// UserInfo defines the fields captured about a user for a Boundary request.
// This type is duplicated in the internal/perms package, but there are circular
// dependency issues.  TBD how to resolve this, but for now, we've dupped it
// here.
//
// fields are intentionally alphabetically ordered so they will match output
// from marshaling event json
type GrantsPair struct {
	Grant   string `json:"grant,omitempty"`
	ScopeId string `json:"scope_id,omitempty"`
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
	const op = "event.WriteInfo"
	eventer, ok := ctx.Value(EventerKey).(*Eventer)
	if !ok {
		return errors.New(errors.InvalidParameter, op, "context missing eventer")
	}
	opts := getOpts(opt...)
	if opts.withDetails == nil && opts.withHeader == nil {
		return errors.New(errors.InvalidParameter, op, "you must specify either header or details options for an event payload")
	}
	if opts.withRequestInfo == nil {
		reqInfo, ok := ctx.Value(RequestInfoKey).(*RequestInfo)
		if !ok {
			return errors.New(errors.InvalidParameter, op, "context missing request info")
		}
		opt = append(opt, WithRequestInfo(reqInfo))
	}

	e, err := NewInfo(caller, opt...)
	if err != nil {
		return errors.Wrap(err, op)
	}
	if err := eventer.Info(ctx, e, opt...); err != nil {
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
		reqInfo, ok := ctx.Value(RequestInfoKey).(*RequestInfo)
		if !ok {
			return errors.New(errors.InvalidParameter, op, "context missing request info")
		}
		opt = append(opt, WithRequestInfo(reqInfo))
	}
	ev, err := NewError(caller, e, opt...)
	if err != nil {
		return errors.Wrap(err, op)
	}
	if err := eventer.Error(ctx, ev); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}
