package event

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/hashicorp/boundary/globals"
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
		return nil, fmt.Errorf("%s: missing context: %w", op, ErrInvalidParameter)
	}
	if eventer == nil {
		return nil, fmt.Errorf("%s: missing eventer: %w", op, ErrInvalidParameter)
	}
	return context.WithValue(ctx, eventerKey, eventer), nil
}

// EventerFromContext attempts to get the eventer value from the context provided
func EventerFromContext(ctx context.Context) (*Eventer, bool) {
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
		return nil, fmt.Errorf("%s: missing context: %w", op, ErrInvalidParameter)
	}
	if info == nil {
		return nil, fmt.Errorf("%s: missing request info: %w", op, ErrInvalidParameter)
	}
	if info.Id == "" {
		return nil, fmt.Errorf("%s: missing request info id: %w", op, ErrInvalidParameter)
	}
	if info.EventId == "" {
		return nil, fmt.Errorf("%s: missing request info event id: %w", op, ErrInvalidParameter)
	}
	return context.WithValue(ctx, requestInfoKey, info), nil
}

// RequestInfoFromContext attempts to get the RequestInfo value from the context
// provided
func RequestInfoFromContext(ctx context.Context) (*RequestInfo, bool) {
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
	if ctx == nil {
		return fmt.Errorf("%s: missing context: %w", op, ErrInvalidParameter)
	}
	if caller == "" {
		return fmt.Errorf("%s: missing operation: %w", op, ErrInvalidParameter)
	}
	eventer, ok := EventerFromContext(ctx)
	if !ok {
		eventer = SysEventer()
		if eventer == nil {
			return fmt.Errorf("%s: missing both context and system eventer: %w", op, ErrInvalidParameter)
		}
	}
	opts := getOpts(opt...)
	if opts.withDetails == nil && opts.withHeader == nil && !opts.withFlush {
		return fmt.Errorf("%s: specify either header or details options for an event payload: %w", op, ErrInvalidParameter)
	}
	if opts.withRequestInfo == nil {
		var err error
		if opt, err = addCtxOptions(ctx, opt...); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	e, err := newObservation(caller, opt...)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := eventer.writeObservation(ctx, e); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// WriteError will write an error event.  It will first check the
// ctx for an eventer, then try event.SysEventer() and if no eventer can be
// found an hclog.Logger will be created and used.
//
// The options WithInfoMsg, WithInfo, WithId and WithRequestInfo are supported
// and all other options are ignored.
func WriteError(ctx context.Context, caller Op, e error, opt ...Option) {
	const op = "event.WriteError"
	// EventerFromContext will handle a nil ctx appropriately. If e or caller is
	// missing, newError(...) will handle them appropriately.
	eventer, ok := EventerFromContext(ctx)
	if !ok {
		eventer = SysEventer()
		if eventer == nil {
			logger := hclog.New(nil)
			logger.Error(fmt.Sprintf("%s: no eventer available to write error: %v", op, e))
			return
		}
	}
	opts := getOpts(opt...)
	if opts.withRequestInfo == nil {
		var err error
		if opt, err = addCtxOptions(ctx, opt...); err != nil {
			eventer.logger.Error(fmt.Sprintf("%s: %v", op, err))
			eventer.logger.Error(fmt.Sprintf("%s: unable to process context options to write error: %v", op, e))
			return
		}
	}
	ev, err := newError(caller, e, opt...)
	if err != nil {
		eventer.logger.Error(fmt.Sprintf("%s: %v", op, err))
		eventer.logger.Error(fmt.Sprintf("%s: unable to create new error to write error: %v", op, e))
		return
	}
	if err := eventer.writeError(ctx, ev); err != nil {
		eventer.logger.Error(fmt.Sprintf("%s: %v", op, err))
		eventer.logger.Error(fmt.Sprintf("%s: unable to write error: %v", op, e))
		return
	}
}

// WriteAudit will write an audit event.  It will first check the ctx for an
// eventer, then try event.SysEventer() and if no eventer can be found an error
// is returned.
//
// At least one and any combination of the supported options may be used:
// WithRequest, WithResponse, WithAuth, WithId, WithFlush and WithRequestInfo.
// All other options are ignored.
func WriteAudit(ctx context.Context, caller Op, opt ...Option) error {
	// TODO (jimlambrt) 6/2021: remove this feature flag envvar when events are
	// generally available.
	if !strings.EqualFold(os.Getenv(globals.BOUNDARY_DEVELOPER_ENABLE_EVENTS), "true") {
		return nil
	}
	const op = "event.WriteAudit"
	if ctx == nil {
		return fmt.Errorf("%s: missing context: %w", op, ErrInvalidParameter)
	}
	if caller == "" {
		return fmt.Errorf("%s: missing operation: %w", op, ErrInvalidParameter)
	}
	eventer, ok := EventerFromContext(ctx)
	if !ok {
		eventer = SysEventer()
		if eventer == nil {
			return fmt.Errorf("%s: missing both context and system eventer: %w", op, ErrInvalidParameter)
		}
	}
	opts := getOpts(opt...)
	if opts.withRequestInfo == nil {
		var err error
		if opt, err = addCtxOptions(ctx, opt...); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	e, err := newAudit(caller, opt...)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := eventer.writeAudit(ctx, e); err != nil {
		return fmt.Errorf("%s: %w", op, err)
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
			// there's no RequestInfo, so there's no id associated with the
			// event and we'll generate one and flush the event
			// since there will never be another with the same id
			id, err := NewId(idPrefix)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			retOpts = append(retOpts, WithId(id))
			if !opts.withFlush {
				retOpts = append(retOpts, WithFlush())
			}
			return retOpts, nil
		}
		retOpts = append(retOpts, WithRequestInfo(reqInfo))
		switch reqInfo.EventId {
		case "":
			// there's no RequestInfo.EventId associated with the observation,
			// so we'll generate one and flush the observation since there will
			// never be another with the same id
			id, err := NewId("e")
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			retOpts = append(retOpts, WithId(id))
			if !opts.withFlush {
				retOpts = append(retOpts, WithFlush())
			}
			return retOpts, nil
		default:
			retOpts = append(retOpts, WithId(reqInfo.EventId))
		}
	}
	return retOpts, nil
}

// WriteSysEvent will write a sysevent using the eventer from
// event.SysEventer() if no eventer can be found an hclog.Logger will be created
// and used. The args are and optional set of key/value pairs about the event.
//
// This function should never be used when sending events while
// handling API requests.
func WriteSysEvent(ctx context.Context, caller Op, msg string, args ...interface{}) {
	const op = "event.WriteSysEvent"

	info := ConvertArgs(args...)
	if msg == "" && info == nil {
		return
	}
	if info == nil {
		info = make(map[string]interface{}, 1)
	}
	info[msgField] = msg

	if caller == "" {
		pc, _, _, ok := runtime.Caller(1)
		details := runtime.FuncForPC(pc)
		if ok && details != nil {
			caller = Op(details.Name())
		} else {
			caller = "unknown operation"
		}
	}

	eventer, ok := EventerFromContext(ctx)
	if !ok {
		eventer = SysEventer()
		if eventer == nil {
			logger := hclog.New(nil)
			logger.Error(fmt.Sprintf("%s: no eventer available to write sysevent: (%s) %+v", op, caller, info))
			return
		}
	}

	id, err := NewId(string(SystemType))
	if err != nil {
		eventer.logger.Error(fmt.Sprintf("%s: %v", op, err))
		eventer.logger.Error(fmt.Sprintf("%s: unable to generate id while writing sysevent: (%s) %+v", op, caller, info))
	}

	e := &sysEvent{
		Id:      Id(id),
		Version: sysVersion,
		Op:      caller,
		Data:    info,
	}
	if err := eventer.writeSysEvent(ctx, e); err != nil {
		eventer.logger.Error(fmt.Sprintf("%s: %v", op, err))
		eventer.logger.Error(fmt.Sprintf("%s: unable to write sysevent: (%s) %+v", op, caller, e))
		return
	}
}

// MissingKey defines a key to be used as the "missing key" when ConvertArgs has
// an odd number of args (it's missing a key in its key/value pairs)
const MissingKey = "EXTRA_VALUE_AT_END"

// ConvertArgs will convert the key/value pair args to a map.  If the args
// provided are an odd number (they're missing a key in their key/value pairs)
// then MissingKey is used to the missing key.
func ConvertArgs(args ...interface{}) map[string]interface{} {
	if len(args) == 0 {
		return nil
	}
	if len(args)%2 != 0 {
		extra := args[len(args)-1]
		args = append(args[:len(args)-1], MissingKey, extra)
	}

	m := map[string]interface{}{}
	for i := 0; i < len(args); i = i + 2 {
		var key string
		switch st := args[i].(type) {
		case string:
			key = st
		default:
			key = fmt.Sprintf("%v", st)
		}
		m[key] = args[i+1]
	}
	return m
}
