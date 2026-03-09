// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"crypto/rand"
	"io"
	"net"
	"time"

	"github.com/hashicorp/boundary/globals"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	intglobals "github.com/hashicorp/boundary/internal/globals"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
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
	WithDefaultClientPort      uint32
	WithLimit                  int
	WithProjectId              string
	WithProjectIds             []string
	WithProjectName            string
	WithUserId                 string
	WithType                   globals.Subtype
	WithHostSources            []string
	WithCredentialLibraries    []*CredentialLibrary
	WithStaticCredentials      []*StaticCredential
	WithSessionMaxSeconds      uint32
	WithSessionConnectionLimit int32
	WithPermissions            []perms.Permission
	WithPublicId               string
	WithWorkerFilter           string
	WithTestWorkerFilter       string
	WithEgressWorkerFilter     string
	WithIngressWorkerFilter    string
	WithTargetIds              []string
	WithAddress                string
	WithStorageBucketId        string
	WithEnableSessionRecording bool
	WithNetResolver            intglobals.NetIpResolver
	WithStartPageAfterItem     pagination.Item
	WithAlias                  *talias.Alias
	withAliases                []*talias.Alias
	withTargetId               string
	withRandomReader           io.Reader
}

func getDefaultOptions() options {
	return options{
		WithName:                   "",
		WithDescription:            "",
		WithLimit:                  0,
		WithDefaultPort:            0,
		WithDefaultClientPort:      0,
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
		WithTestWorkerFilter:       "",
		WithEgressWorkerFilter:     "",
		WithIngressWorkerFilter:    "",
		WithAddress:                "",
		WithNetResolver:            net.DefaultResolver,
		withTargetId:               "",
		withRandomReader:           rand.Reader,
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

// WithDefaultClientPort provides an option to specify the default client listening port.
func WithDefaultClientPort(p uint32) Option {
	return func(o *options) {
		o.WithDefaultClientPort = p
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
func WithType(t globals.Subtype) Option {
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

// WithTestWorkerFilter provides an optional worker filter used only in testing
func WithTestWorkerFilter(filter string) Option {
	return func(o *options) {
		o.WithTestWorkerFilter = filter
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

// WithAddress provides an optional network address
func WithAddress(address string) Option {
	return func(o *options) {
		o.WithAddress = address
	}
}

// WithEnableSessionRecording provides an option to enable session recording on
// the target
func WithEnableSessionRecording(enable bool) Option {
	return func(o *options) {
		o.WithEnableSessionRecording = enable
	}
}

// WithStorageBucketId provides an option to set a storage bucket on a target
func WithStorageBucketId(id string) Option {
	return func(o *options) {
		o.WithStorageBucketId = id
	}
}

// WithNetResolver provides an option to specify a custom DNS resolver
func WithNetResolver(resolver intglobals.NetIpResolver) Option {
	return func(o *options) {
		o.WithNetResolver = resolver
	}
}

// WithStartPageAfterItem is used to paginate over the results.
// The next page will start after the provided item.
func WithStartPageAfterItem(item pagination.Item) Option {
	return func(o *options) {
		o.WithStartPageAfterItem = item
	}
}

// WithAliases provides an option to provide aliases.
func WithAliases(in []*talias.Alias) Option {
	return func(o *options) {
		o.withAliases = in
	}
}

// WithAlias provides an option to provide a single alias.
func WithAlias(in *talias.Alias) Option {
	return func(o *options) {
		o.WithAlias = in
	}
}

// WithTargetId provides an option to provide a target ID.
func WithTargetId(in string) Option {
	return func(o *options) {
		o.withTargetId = in
	}
}

// WithRandomReader provides an option to specify a random reader.
func WithRandomReader(reader io.Reader) Option {
	return func(o *options) {
		o.withRandomReader = reader
	}
}
