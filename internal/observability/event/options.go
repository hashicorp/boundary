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
	withInfo          map[string]interface{}
	withInfoMsg       string
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
	withSysSink         bool   // test only option
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

// I represents optional information about an error or system event
type I map[string]interface{}

// H represents optional header level data/info about an observation event.
// There is only one "header" for an observation.
type H map[string]interface{}

// D represents optional detail level data/info about an observation event.
// There can be multiple details for an observation.
type D map[string]interface{}

// WithInfo allows an optional map as info about an error event. If used along
// with WithInfoMsg(...) any value for key "msg" within the I passed to WithInfo
// will be overridden by the msg passed into WithInfoMsg(...)
func WithInfo(i I) Option {
	return func(o *options) {
		o.withInfo = i
	}
}

// WithInfoMsg allows an optional msg about and error event.  If used along with
// WithInfo(...) any value for key "msg" within the I passed into WithInfo will
// be overridden by this option.
func WithInfoMsg(msg string) Option {
	return func(o *options) {
		o.withInfoMsg = msg
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
