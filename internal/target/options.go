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
	withScopeIds               []string
	withScopeName              string
	withUserId                 string
	withTargetType             *TargetType
	withHostSources            []string
	withCredentialSources      []string
	withSessionMaxSeconds      uint32
	withSessionConnectionLimit int32
	withPublicId               string
	withWorkerFilter           string
}

func getDefaultOptions() options {
	return options{
		withName:                   "",
		withDescription:            "",
		withLimit:                  0,
		withDefaultPort:            0,
		withScopeId:                "",
		withScopeIds:               nil,
		withScopeName:              "",
		withUserId:                 "",
		withTargetType:             nil,
		withHostSources:            nil,
		withCredentialSources:      nil,
		withSessionMaxSeconds:      uint32((8 * time.Hour).Seconds()),
		withSessionConnectionLimit: 1,
		withPublicId:               "",
		withWorkerFilter:           "",
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

// WithScopeId provides an option to search by multiple scope id
func WithScopeIds(scopeIds []string) Option {
	return func(o *options) {
		o.withScopeIds = scopeIds
	}
}

// WithScopeId provides an option to search by a scope name
func WithScopeName(scopeName string) Option {
	return func(o *options) {
		o.withScopeName = scopeName
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

// WithHostSources provides an option for providing a list of host source ids
func WithHostSources(hs []string) Option {
	return func(o *options) {
		o.withHostSources = hs
	}
}

// WithCredentialSources provides an option for providing a list of credential source ids
func WithCredentialSources(cl []string) Option {
	return func(o *options) {
		o.withCredentialSources = cl
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

// WithWorkerFilter provides an optional worker filter
func WithWorkerFilter(filter string) Option {
	return func(o *options) {
		o.withWorkerFilter = filter
	}
}
