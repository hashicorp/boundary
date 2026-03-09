// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package common

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
)

// GeneratedTraceId returns a boundary generated TraceId or "" if an error occurs when generating
// the id.
func GeneratedTraceId(ctx context.Context) string {
	t, err := base62.Random(20)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("gtraceid_%s", t)
}

type writerWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (w *writerWrapper) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *writerWrapper) StatusCode() int {
	return w.statusCode
}

// WrapWithOptionals will test the wrap ResponseWriter and test it for various
// optional interfaces: http.Flusher, http.Pusher and http.Hijacker.  It return
// an http.ResponseWriter that satisfies those optional interfaces.
//
// See: https://medium.com/@cep21/interface-wrapping-method-erasure-c523b3549912
func WrapWithOptionals(ctx context.Context, with *writerWrapper, wrap http.ResponseWriter) (http.ResponseWriter, error) {
	const op = "common.WrapWithOptionals"
	if with == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing writer wrapper")
	}
	if wrap == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing response writer")
	}
	flusher, _ := wrap.(http.Flusher)
	pusher, _ := wrap.(http.Pusher)
	hijacker, _ := wrap.(http.Hijacker)
	switch {
	case flusher == nil && pusher == nil && hijacker == nil:
		return with, nil
	case flusher != nil && pusher == nil && hijacker == nil:
		return struct {
			*writerWrapper
			http.Flusher
		}{with, flusher}, nil
	case flusher == nil && pusher != nil && hijacker == nil:
		return struct {
			*writerWrapper
			http.Pusher
		}{with, pusher}, nil
	case flusher == nil && pusher == nil && hijacker != nil:
		return struct {
			*writerWrapper
			http.Hijacker
		}{with, hijacker}, nil
	case flusher != nil && pusher != nil && hijacker == nil:
		return struct {
			*writerWrapper
			http.Flusher
			http.Pusher
		}{with, flusher, pusher}, nil
	case flusher != nil && pusher == nil && hijacker != nil:
		return struct {
			*writerWrapper
			http.Flusher
			http.Hijacker
		}{with, flusher, hijacker}, nil
	case flusher == nil && pusher != nil && hijacker != nil:
		return struct {
			*writerWrapper
			http.Pusher
			http.Hijacker
		}{with, pusher, hijacker}, nil
	default:
		return struct {
			*writerWrapper
			http.Flusher
			http.Pusher
			http.Hijacker
		}{with, flusher, pusher, hijacker}, nil
	}
}

// WrapWithEventsHandler will wrap the provided http.Handler with a
// handler that adds an Eventer to the request context and starts/flushes gated
// events of type: observation and audit
func WrapWithEventsHandler(ctx context.Context, h http.Handler, e *event.Eventer, kms *kms.Kms, listenerCfg *listenerutil.ListenerConfig) (http.Handler, error) {
	const op = "common.WrapWithEventsHandler"
	if h == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing handler")
	}
	if e == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing eventer")
	}
	if kms == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		publicId, _, _ := auth.GetTokenFromRequest(ctx, kms, r)

		var err error
		id, err := event.NewId(event.IdPrefix)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to create id for event", "method", r.Method, "url", r.URL.RequestURI()))
			return
		}
		clientIp, err := ClientIpFromRequest(ctx, listenerCfg, r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to determine client ip"))
		}
		info := &event.RequestInfo{
			EventId:  id,
			Id:       GeneratedTraceId(ctx),
			PublicId: publicId,
			Method:   r.Method,
			Path:     r.URL.RequestURI(),
			ClientIp: clientIp,
		}
		ctx, err = event.NewRequestInfoContext(ctx, info)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			event.WriteError(r.Context(), op, err, event.WithInfoMsg("unable to create context with request info", "method", r.Method, "url", r.URL.RequestURI()))
			return
		}
		ctx, err = event.NewEventerContext(ctx, e)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			event.WriteError(r.Context(), op, err, event.WithInfoMsg("unable to create context with eventer", "method", r.Method, "url", r.URL.RequestURI()))
			return
		}

		// Set the context back on the request
		r = r.Clone(ctx)

		{
			method := r.Method
			url := r.URL.RequestURI()
			start := time.Now()
			if err := startGatedEvents(ctx, method, url, start); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				event.WriteError(ctx, op, err, event.WithInfoMsg("unable to start gated events"))
				return
			}

			wrapper, err := WrapWithOptionals(ctx, &writerWrapper{w, http.StatusOK}, w)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				event.WriteError(ctx, op, err, event.WithInfoMsg("unable to wrap handler with optional interfaces"))
				return
			}
			h.ServeHTTP(wrapper, r)

			i, _ := wrapper.(interface{ StatusCode() int })
			if err := flushGatedEvents(ctx, method, url, i.StatusCode(), start); err != nil {
				// Intentionally not writing the header/response here, since the
				// header and response have already been written.
				event.WriteError(ctx, op, err, event.WithInfoMsg("unable to flush gated events"))
				return
			}
		}
	}), nil
}

// startGatedEvents will send "initial" events for all event types which are
// gated.  This approach is okay since if at event type isn't enabled sending
// an event for it becomes a no op in the eventlogger.Broker
func startGatedEvents(ctx context.Context, method, url string, startTime time.Time) error {
	const op = "common.startGatedEvents"
	if startTime.IsZero() {
		startTime = time.Now()
	}
	err := event.WriteObservation(ctx, "handler", event.WithHeader("start", startTime))
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write observation event"))
	}

	err = event.WriteAudit(ctx, "handler")
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write audit event"))
	}
	return nil
}

// flushGatedEvents will send flush events for all event types which are
// gated.  This approach is okay since if at event type isn't enabled sending
// an event for it becomes a no op in the eventlogger.Broker
func flushGatedEvents(ctx context.Context, method, url string, statusCode int, startTime time.Time) error {
	const op = "common.flushGatedEvents"
	stopTime := time.Now()
	var latency float64
	if !startTime.IsZero() {
		latency = float64(stopTime.Sub(startTime)) / float64(time.Millisecond)
	}
	err := event.WriteObservation(ctx, "handler", event.WithFlush(),
		event.WithHeader(
			"stop", stopTime,
			"latency-ms", latency,
			"status", statusCode,
		),
	)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write and flush observation event"))
	}
	err = event.WriteAudit(ctx, "handler", event.WithFlush(), event.WithResponse(&event.Response{StatusCode: statusCode}))
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write and flush audit event"))
	}
	return nil
}
