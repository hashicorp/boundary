// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/hashicorp/boundary/internal/test"
)

var (
	ci     bool
	isTest bool
)

type key int

const cancelledSendTimeout = 3 * time.Second

const (
	eventerKey key = iota
	requestInfoKey
	correlationIdKey
)

func init() {
	ci = os.Getenv("CI") != ""
	isTest = test.IsTestRun()
}

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

// NewCorrelationIdContext will return a context containing a value for the
// provided CorrelationId
func NewCorrelationIdContext(ctx context.Context, correlationId string) (context.Context, error) {
	const op = "event.NewCorrelationContext"
	if ctx == nil {
		return nil, fmt.Errorf("%s: missing context: %w", op, ErrInvalidParameter)
	}
	if correlationId == "" {
		return nil, fmt.Errorf("%s: missing correlation id: %w", op, ErrInvalidParameter)
	}
	return context.WithValue(ctx, correlationIdKey, correlationId), nil
}

// CorrelationIdFromContext attempts to get the Correlation Id value from the context
// provided
func CorrelationIdFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	reqInfo, ok := ctx.Value(correlationIdKey).(string)
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
	if opts.withDetails == nil && opts.withHeader == nil && !opts.withFlush && opts.withRequest == nil && opts.withResponse == nil {
		return fmt.Errorf("%s: specify either header or details options or request or response for an event payload: "+
			"%w", op, ErrInvalidParameter)
	}
	// For the case that the telemetry is not enabled, and we have events coming from interceptors.
	// or the case that incoming call only has withDetails without enabling telemetry.
	if !eventer.conf.TelemetryEnabled && (opts.withRequest != nil || opts.withResponse != nil || opts.withDetails != nil) {
		return nil
	}
	// If telemetry is enabled, we add it to the options.
	if eventer.conf.TelemetryEnabled {
		opt = append(opt, WithTelemetry())
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
	sendCtx, sendCancel := newSendCtx(ctx)
	if sendCancel != nil {
		defer sendCancel()
	}
	if err := eventer.writeObservation(sendCtx, e); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// WriteError will write an error event.  It will first check the
// ctx for an eventer, then try event.SysEventer() and if no eventer can be
// found an hclog.Logger will be created and used.  Note: any multierror errors
// will be converted to a stdlib error (because multierror doesn't support json
// marshaling).
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
			switch {
			case !ci:
			case !isTest:
			default:
				fallbackLogger().Error(fmt.Sprintf("%s: no eventer available to write error: %v", op, e))
			}
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
	sendCtx, sendCancel := newSendCtx(ctx)
	if sendCancel != nil {
		defer sendCancel()
	}
	if err := eventer.writeError(sendCtx, ev); err != nil {
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
	if correlationId, ok := CorrelationIdFromContext(ctx); ok {
		opt = append(opt, withCorrelationId(correlationId))
	}
	e, err := newAudit(caller, opt...)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	sendCtx, sendCancel := newSendCtx(ctx)
	if sendCancel != nil {
		defer sendCancel()
	}
	if err := eventer.writeAudit(sendCtx, e); err != nil {
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
			id, err := NewId(IdPrefix)
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
func WriteSysEvent(ctx context.Context, caller Op, msg string, args ...any) {
	const op = "event.WriteSysEvent"

	info := ConvertArgs(args...)
	if msg == "" && info == nil {
		return
	}
	if info == nil {
		info = make(map[string]any, 1)
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
			fallbackLogger().Error(fmt.Sprintf("%s: no eventer available to write sysevent: (%s) %+v", op, caller, info))
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
	sendCtx, sendCancel := newSendCtx(ctx)
	if sendCancel != nil {
		defer sendCancel()
	}
	if err := eventer.writeSysEvent(sendCtx, e); err != nil {
		eventer.logger.Error(fmt.Sprintf("%s: %v", op, err))
		eventer.logger.Error(fmt.Sprintf("%s: unable to write sysevent: (%s) %+v", op, caller, e))
		return
	}
}

func newSendCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	var sendCtx context.Context
	var sendCancel context.CancelFunc
	switch {
	case ctx == nil:
		return context.Background(), nil
	case ctx.Err() == context.Canceled || ctx.Err() == context.DeadlineExceeded:
		sendCtx, sendCancel = context.WithTimeout(context.Background(), cancelledSendTimeout)
		info, ok := RequestInfoFromContext(ctx)
		if ok {
			reqCtx, err := NewRequestInfoContext(sendCtx, info)
			if err == nil {
				sendCtx = reqCtx
			}
		}
	default:
		sendCtx = ctx
	}
	return sendCtx, sendCancel
}

// MissingKey defines a key to be used as the "missing key" when ConvertArgs has
// an odd number of args (it's missing a key in its key/value pairs)
const MissingKey = "EXTRA_VALUE_AT_END"

// ConvertArgs will convert the key/value pair args to a map.  If the args
// provided are an odd number (they're missing a key in their key/value pairs)
// then MissingKey is used to the missing key.
func ConvertArgs(args ...any) map[string]any {
	if len(args) == 0 {
		return nil
	}
	if len(args)%2 != 0 {
		extra := args[len(args)-1]
		args = append(args[:len(args)-1], MissingKey, extra)
	}

	m := map[string]any{}
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
