package event

import (
	"time"
)

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct {
	withId          string
	withDetails     map[string]interface{}
	withHeader      map[string]interface{}
	withFlush       bool
	withRequestInfo *RequestInfo
	withNow         time.Time
	withRequest     *Request
	withResponse    *Response
	withAuth        *Auth
}

func getDefaultOptions() options {
	return options{}
}

func WithId(id string) Option {
	return func(o *options) {
		o.withId = id
	}
}

func WithDetails(d map[string]interface{}) Option {
	return func(o *options) {
		o.withDetails = d
	}
}

func WithHeader(d map[string]interface{}) Option {
	return func(o *options) {
		o.withHeader = d
	}
}

func WithFlush() Option {
	return func(o *options) {
		o.withFlush = true
	}
}

func WithRequestInfo(i *RequestInfo) Option {
	return func(o *options) {
		o.withRequestInfo = i
	}
}

func WithNow(now time.Time) Option {
	return func(o *options) {
		o.withNow = now
	}
}

func WithRequest(r *Request) Option {
	return func(o *options) {
		o.withRequest = r
	}
}

func WithResponse(r *Response) Option {
	return func(o *options) {
		o.withResponse = r
	}
}

func WithAuth(a *Auth) Option {
	return func(o *options) {
		o.withAuth = a
	}
}
