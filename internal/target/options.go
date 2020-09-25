package target

import "time"

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withName                   string
	withDescription            string
	withDefaultPort            uint32
	withLimit                  int
	withScopeId                string
	withUserId                 string
	withTargetType             *TargetType
	withHostSets               []string
	withSessionMaxSeconds      uint32
	withSessionConnectionLimit int32
	withPublicId               string
}

func getDefaultOptions() options {
	return options{
		withName:                   "",
		withDescription:            "",
		withLimit:                  0,
		withDefaultPort:            0,
		withScopeId:                "",
		withUserId:                 "",
		withTargetType:             nil,
		withHostSets:               nil,
		withSessionMaxSeconds:      uint32((8 * time.Hour).Seconds()),
		withSessionConnectionLimit: 1,
		withPublicId:               "",
	}
}

// WithDescription provides an optional description
func WithDescription(desc string) Option {
	return func(o *options) {
		o.withDescription = desc
	}
}

// WithName provides an option to search by a friendly name
func WithName(name string) Option {
	return func(o *options) {
		o.withName = name
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

// WithDefaultPort provides an option to specify the default target port.
func WithDefaultPort(p uint32) Option {
	return func(o *options) {
		o.withDefaultPort = p
	}
}

// WithScopeId provides an option to search by a scope id
func WithScopeId(scopeId string) Option {
	return func(o *options) {
		o.withScopeId = scopeId
	}
}

// WithUserId provides an option to search by a user public id
func WithUserId(userId string) Option {
	return func(o *options) {
		o.withUserId = userId
	}
}

// WithTargetType provides an option to search by a target type
func WithTargetType(t TargetType) Option {
	return func(o *options) {
		o.withTargetType = &t
	}
}

// WithHostSets provides an option for providing a list of host set ids
func WithHostSets(hs []string) Option {
	return func(o *options) {
		o.withHostSets = hs
	}
}

func WithSessionMaxSeconds(dur uint32) Option {
	return func(o *options) {
		o.withSessionMaxSeconds = dur
	}
}

func WithSessionConnectionLimit(limit int32) Option {
	return func(o *options) {
		o.withSessionConnectionLimit = limit
	}
}

// WithPublicId provides an optional public id
func WithPublicId(id string) Option {
	return func(o *options) {
		o.withPublicId = id
	}
}
