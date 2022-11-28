package target

import (
	"time"

	"github.com/hashicorp/boundary/internal/perms"
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
	WithProjectId              string
	WithProjectIds             []string
	WithProjectName            string
	WithUserId                 string
	WithType                   subtypes.Subtype
	WithHostSources            []string
	WithCredentialLibraries    []*CredentialLibrary
	WithStaticCredentials      []*StaticCredential
	WithSessionMaxSeconds      uint32
	WithSessionConnectionLimit int32
	WithPermissions            []perms.Permission
	WithPublicId               string
	WithWorkerFilter           string
	WithEgressWorkerFilter     string
	WithIngressWorkerFilter    string
	WithTargetIds              []string
}

func getDefaultOptions() options {
	return options{
		WithName:                   "",
		WithDescription:            "",
		WithLimit:                  0,
		WithDefaultPort:            0,
		WithProjectId:              "",
		WithProjectIds:             nil,
		WithProjectName:            "",
		WithUserId:                 "",
		WithType:                   "",
		WithHostSources:            nil,
		WithCredentialLibraries:    nil,
		WithStaticCredentials:      nil,
		WithSessionMaxSeconds:      uint32((8 * time.Hour).Seconds()),
		WithSessionConnectionLimit: -1,
		WithPermissions:            nil,
		WithPublicId:               "",
		WithWorkerFilter:           "",
		WithEgressWorkerFilter:     "",
		WithIngressWorkerFilter:    "",
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

// WithProjectId provides an option to search by a project id
func WithProjectId(projectId string) Option {
	return func(o *options) {
		o.WithProjectId = projectId
	}
}

// WithProjectId provides an option to search by multiple project id
func WithProjectIds(projectIds []string) Option {
	return func(o *options) {
		o.WithProjectIds = projectIds
	}
}

// WithProjectId provides an option to search by a project name
func WithProjectName(projectName string) Option {
	return func(o *options) {
		o.WithProjectName = projectName
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

// WithEgressWorkerFilter provides an optional egress worker filter
func WithEgressWorkerFilter(filter string) Option {
	return func(o *options) {
		o.WithEgressWorkerFilter = filter
	}
}

// WithIngressWorkerFilter provides an optional ingress worker filter
func WithIngressWorkerFilter(filter string) Option {
	return func(o *options) {
		o.WithIngressWorkerFilter = filter
	}
}

// WithTargetIds provides an option to search by specific target IDs
func WithTargetIds(with []string) Option {
	return func(o *options) {
		o.WithTargetIds = with
	}
}

// WithPermissions is used by this repo to restrict a list
// request's results based on the given set of permissions.
func WithPermissions(perms []perms.Permission) Option {
	return func(o *options) {
		o.WithPermissions = perms
	}
}
