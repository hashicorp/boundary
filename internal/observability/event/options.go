package event

import (
	"time"
)

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
	withId            string
	withDetails       map[string]interface{}
	withHeader        map[string]interface{}
	withFlush         bool
	withRequestInfo   *RequestInfo
	withNow           time.Time
	withRequest       *Request
	withResponse      *Response
	withAuth          *Auth
	withEventer       *Eventer
	withEventerConfig *EventerConfig

	withBroker          broker // test only option
	withAuditSink       bool   // test only option
	withObservationSink bool   // test only option
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

// WithDetails allows an optional map as details
func WithDetails(d map[string]interface{}) Option {
	return func(o *options) {
		o.withDetails = d
	}
}

// WithHeader allows an optional map as a header
func WithHeader(d map[string]interface{}) Option {
	return func(o *options) {
		o.withHeader = d
	}
}

// WithFlush allows an optional flush option.
func WithFlush() Option {
	return func(o *options) {
		o.withFlush = true
	}
}

// WithRequestInfo allows an optional RequestInfo
func WithRequestInfo(i *RequestInfo) Option {
	return func(o *options) {
		o.withRequestInfo = i
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
