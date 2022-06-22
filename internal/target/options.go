package target

import (
	"time"

	"github.com/hashicorp/boundary/internal/types/subtypes"
)

// GetOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) options {
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
	WithName                   string
	WithDescription            string
	WithDefaultPort            uint32
	WithLimit                  int
	WithScopeId                string
	WithScopeIds               []string
	WithScopeName              string
	WithUserId                 string
	WithType                   subtypes.Subtype
	WithHostSources            []string
	WithCredentialLibraries    []*CredentialLibrary
	WithStaticCredentials      []*StaticCredential
	WithSessionMaxSeconds      uint32
	WithSessionConnectionLimit int32
	WithPublicId               string
	WithWorkerFilter           string
	WithTargetIds              []string
}

func getDefaultOptions() options {
	return options{
		WithName:                   "",
		WithDescription:            "",
		WithLimit:                  0,
		WithDefaultPort:            0,
		WithScopeId:                "",
		WithScopeIds:               nil,
		WithScopeName:              "",
		WithUserId:                 "",
		WithType:                   "",
		WithHostSources:            nil,
		WithCredentialLibraries:    nil,
		WithStaticCredentials:      nil,
		WithSessionMaxSeconds:      uint32((8 * time.Hour).Seconds()),
		WithSessionConnectionLimit: 1,
		WithPublicId:               "",
		WithWorkerFilter:           "",
	}
}

// WithDescription provides an optional description
func WithDescription(desc string) Option {
	return func(o *options) {
		o.WithDescription = desc
	}
}

// WithName provides an option to search by a friendly name
func WithName(name string) Option {
	return func(o *options) {
		o.WithName = name
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.WithLimit = limit
	}
}

// WithDefaultPort provides an option to specify the default target port.
func WithDefaultPort(p uint32) Option {
	return func(o *options) {
		o.WithDefaultPort = p
	}
}

// WithScopeId provides an option to search by a scope id
func WithScopeId(scopeId string) Option {
	return func(o *options) {
		o.WithScopeId = scopeId
	}
}

// WithScopeId provides an option to search by multiple scope id
func WithScopeIds(scopeIds []string) Option {
	return func(o *options) {
		o.WithScopeIds = scopeIds
	}
}

// WithScopeId provides an option to search by a scope name
func WithScopeName(scopeName string) Option {
	return func(o *options) {
		o.WithScopeName = scopeName
	}
}

// WithUserId provides an option to search by a user public id
func WithUserId(userId string) Option {
	return func(o *options) {
		o.WithUserId = userId
	}
}

// WithType provides an option to search by a target type
func WithType(t subtypes.Subtype) Option {
	return func(o *options) {
		o.WithType = t
	}
}

// WithHostSources provides an option for providing a list of host source ids
func WithHostSources(hs []string) Option {
	return func(o *options) {
		o.WithHostSources = hs
	}
}

// WithCredentialLibraries provides an option for providing a list of credential libraries.
func WithCredentialLibraries(cl []*CredentialLibrary) Option {
	return func(o *options) {
		o.WithCredentialLibraries = cl
	}
}

// WithStaticCredentials provides an option for providing a list of static credentials.
func WithStaticCredentials(c []*StaticCredential) Option {
	return func(o *options) {
		o.WithStaticCredentials = c
	}
}

func WithSessionMaxSeconds(dur uint32) Option {
	return func(o *options) {
		o.WithSessionMaxSeconds = dur
	}
}

func WithSessionConnectionLimit(limit int32) Option {
	return func(o *options) {
		o.WithSessionConnectionLimit = limit
	}
}

// WithPublicId provides an optional public id
func WithPublicId(id string) Option {
	return func(o *options) {
		o.WithPublicId = id
	}
}

// WithWorkerFilter provides an optional worker filter
func WithWorkerFilter(filter string) Option {
	return func(o *options) {
		o.WithWorkerFilter = filter
	}
}

// WithTargetIds provides an option to search by specific target IDs
func WithTargetIds(with []string) Option {
	return func(o *options) {
		o.WithTargetIds = with
	}
}
