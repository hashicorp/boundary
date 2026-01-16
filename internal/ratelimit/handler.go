// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"regexp"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-rate"
)

var (
	errUnknownResource   = &extractResourceActionErr{http.StatusNotFound, "unknown resource"}
	errUnknownAction     = &extractResourceActionErr{http.StatusBadRequest, "unknown action"}
	errUnsupportedAction = &extractResourceActionErr{http.StatusMethodNotAllowed, "invalid action"}
)

type extractResourceActionErr struct {
	statusCode int
	msg        string
}

func (e *extractResourceActionErr) Error() string {
	return e.msg
}

var pathRegex = regexp.MustCompile(`/v1/(?P<resource>[\w-]+)((/(?P<id>[^:]+))?(:(?P<action>[\w-:]+)?)?)?`)

func extractResourceAction(path, method string) (res, act string, err error) {
	var id string

	var r resource.Type
	var ok bool
	var actionSet action.ActionSet

	// TODO: replace regex with lexer
	match := pathRegex.FindStringSubmatch(path)
	for i, name := range pathRegex.SubexpNames() {
		switch name {
		case "resource":
			res = match[i]
			r, ok = resource.FromPlural(res)
			if !ok {
				res = resource.Unknown.String()
				err = errUnknownResource
				return res, act, err
			}
			res = r.String()
		case "action":
			act = match[i]
			if act != "" {
				actionSet, err = action.ActionSetForResource(r)
				if err != nil {
					act = action.Unknown.String()
					err = errUnknownAction
					return res, act, err
				}
				at, ok := action.Map[act]
				if !ok {
					act = action.Unknown.String()
					err = errUnknownAction
					return res, act, err
				}
				if !actionSet.HasAction(at) {
					err = errUnsupportedAction
					return res, act, err
				}
			}
		case "id":
			id = match[i]
		}
	}

	switch act {
	case "":
		switch id {
		case "":
			switch method {
			case http.MethodGet:
				act = action.List.String()
			case http.MethodPost:
				act = action.Create.String()
			default:
				act = action.Unknown.String()
				err = errUnsupportedAction
				return res, act, err
			}
		default:
			switch method {
			case http.MethodGet:
				act = action.Read.String()
			case http.MethodDelete:
				act = action.Delete.String()
			case http.MethodPatch:
				act = action.Update.String()
			default:
				act = action.Unknown.String()
				err = errUnsupportedAction
				return res, act, err
			}
		}
	}
	return res, act, err
}

// LimiterFunc returns a rate.Limiter
type LimiterFunc func() Limiter

// Handler is an http middleware handler that checks if a request is allowed
// using the rate limiter returned by f. If the request is allowed, the next handler
// is called. Otherwise a 429 is returned with the Retry-After response header
// set to the number of seconds the client should wait to make it's next request.
func Handler(ctx context.Context, f LimiterFunc, next http.Handler) http.Handler {
	const op = "ratelimit.Handler"
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		l := f()

		reqInfo, ok := event.RequestInfoFromContext(req.Context())
		if !ok || reqInfo == nil || reqInfo.ClientIp == "" {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		authtoken, ok := req.Context().Value(globals.ContextAuthTokenPublicIdKey).(string)
		if !ok {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		res, a, err := extractResourceAction(req.URL.Path, req.Method)
		if err != nil {
			if extractErr, ok := err.(*extractResourceActionErr); ok {
				rw.WriteHeader(extractErr.statusCode)
				return
			}
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		allowed, quota, err := l.Allow(res, a, reqInfo.ClientIp, authtoken)
		if err != nil {
			if errFull, ok := err.(*rate.ErrLimiterFull); ok {
				rw.Header().Add("Retry-After", fmt.Sprintf("%.0f", math.Ceil(errFull.RetryIn.Seconds())))
				rw.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			// The only other error here should be rate.ErrLimitNotFound, which
			// shouldn't be possible given how we initialize the limiter and
			// the checks done by extractResourceAction.
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		l.SetUsageHeader(quota, rw.Header())
		if err := l.SetPolicyHeader(res, a, rw.Header()); err != nil {
			// Wrap error to emit an error event. An error here would be
			// unexpected, since the only possible error would be
			// ErrLimitPolicyNotFound which would have been returned by Allow
			// and handled above. And even that would be unexpected, given how
			// the limiter is initialized and the checks done by
			// extractResourceAction.
			event.WriteError(ctx, op, fmt.Errorf("failed to set policy header: %w", err))
		}

		if !allowed {
			rw.Header().Add("Retry-After", fmt.Sprintf("%.0f", math.Ceil(quota.ResetsIn().Seconds())))
			rw.WriteHeader(http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(rw, req)
	})
}
