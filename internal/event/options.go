// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"net/url"
	"time"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

const msgField = "msg"

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct {
	withId               string
	withDetails          map[string]any
	withHeader           map[string]any
	withFlush            bool
	withInfo             map[string]any
	withRequestInfo      *RequestInfo
	withNow              time.Time
	withRequest          *Request
	withResponse         *Response
	withAuth             *Auth
	withEventer          *Eventer
	withEventerConfig    *EventerConfig
	withAllow            []string
	withDeny             []string
	withSchema           *url.URL
	withAuditWrapper     wrapping.Wrapper
	withFilterOperations AuditFilterOperations
	withGating           bool
	withNoGateLocking    bool
	withTelemetry        bool
	withCorrelationId    string

	// These options are related to the hclog adapter
	withHclogLevel hclog.Level

	withBroker          broker     // test only option
	withStderrSink      bool       // test only option
	withAuditSink       bool       // test only option
	withObservationSink bool       // test only option
	withSysSink         bool       // test only option
	withSinkFormat      SinkFormat // test only option
	withNoDefaultSink   bool       // test only option
}

func getDefaultOptions() options {
	return options{}
}

// WithId allows an optional Id
func WithId(id string) Option {
	return func(o *options) {
		o.withId = id
	}
}

// WithDetails allows an optional set of key/value pairs about an observation
// event at the detail level and observation events may have multiple "details"
func WithDetails(args ...any) Option {
	return func(o *options) {
		o.withDetails = ConvertArgs(args...)
	}
}

// WithHeader allows an optional set of key/value pairs about an event at the
// header level and observation events will only have one "header"
func WithHeader(args ...any) Option {
	return func(o *options) {
		o.withHeader = ConvertArgs(args...)
	}
}

// WithFlush allows an optional flush option.
func WithFlush() Option {
	return func(o *options) {
		o.withFlush = true
	}
}

// WithInfo allows an optional info key/value pairs about an error event.  If
// used in conjunction with the WithInfoMsg(...) option, and WithInfoMsg(...) is
// specified after WithInfo(...), then WithInfoMsg(...) will overwrite any
// values from WithInfo(...).  It's recommend that these two options not be used
// together.
func WithInfo(args ...any) Option {
	return func(o *options) {
		o.withInfo = ConvertArgs(args...)
	}
}

// WithInfoMsg allows an optional msg and optional info key/value pairs about an
// error event. If used in conjunction with the WithInfo(...) option, and
// WithInfo(...) is specified after WithInfoMsg(...), then WithInfo(...) will
// overwrite any values from WithInfo(...).  It's recommend that these two
// options not be used together.
func WithInfoMsg(msg string, args ...any) Option {
	return func(o *options) {
		o.withInfo = ConvertArgs(args...)
		if o.withInfo == nil {
			o.withInfo = map[string]any{
				msgField: msg,
			}
			return
		}
		o.withInfo[msgField] = msg
	}
}

// WithRequestInfo allows an optional RequestInfo
func WithRequestInfo(i *RequestInfo) Option {
	return func(o *options) {
		o.withRequestInfo = i
	}
}

// withCorrelationId allows an optional CorrelationId
func withCorrelationId(id string) Option {
	return func(o *options) {
		o.withCorrelationId = id
	}
}

// WithNow allows an option time.Time to represent now.
func WithNow(now time.Time) Option {
	return func(o *options) {
		o.withNow = now
	}
}

// WithRequest allows an optional request
func WithRequest(r *Request) Option {
	return func(o *options) {
		o.withRequest = r
	}
}

// WithResponse allows an optional response
func WithResponse(r *Response) Option {
	return func(o *options) {
		o.withResponse = r
	}
}

// WithAuth allows an optional Auth
func WithAuth(a *Auth) Option {
	return func(o *options) {
		o.withAuth = a
	}
}

// WithEventer allows an optional eventer
func WithEventer(e *Eventer) Option {
	return func(o *options) {
		o.withEventer = e
	}
}

// WithEventer allows an optional eventer config
func WithEventerConfig(c *EventerConfig) Option {
	return func(o *options) {
		o.withEventerConfig = c
	}
}

// WithSchema is an optional schema for the cloudevents
func WithSchema(url *url.URL) Option {
	return func(o *options) {
		o.withSchema = url
	}
}

// WithAllow is an optional set of allow filters
func WithAllow(f ...string) Option {
	return func(o *options) {
		o.withAllow = f
	}
}

// WithDeny is an optional set of deny filters
func WithDeny(f ...string) Option {
	return func(o *options) {
		o.withDeny = f
	}
}

// WithAuditWrapper is an optional wrapper for audit events
func WithAuditWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withAuditWrapper = w
	}
}

// WithFilterOperations is an optional set of filter operations
func WithFilterOperations(fop AuditFilterOperations) Option {
	return func(o *options) {
		o.withFilterOperations = fop
	}
}

// WithHclogLevel is an option to specify a log level if using the adapter
func WithHclogLevel(with hclog.Level) Option {
	return func(o *options) {
		o.withHclogLevel = with
	}
}

// WithGating starts the eventer in gated mode
func WithGating(with bool) Option {
	return func(o *options) {
		o.withGating = with
	}
}

// WithNoGateLocking is used when trawling through the existing queue to ensure we don't deadlock
func WithNoGateLocking(with bool) Option {
	return func(o *options) {
		o.withNoGateLocking = with
	}
}

// WithTelemetry allows an optional telemetry option.
func WithTelemetry() Option {
	return func(o *options) {
		o.withTelemetry = true
	}
}
