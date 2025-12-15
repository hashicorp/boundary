// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/pagination"
	"google.golang.org/protobuf/types/known/structpb"
)

// getOpts - iterate the inbound Options and return a struct
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
	withPublicId            string
	withPluginId            string
	withName                string
	withExternalName        string
	withDescription         string
	withAttributes          *structpb.Struct
	withSecrets             *structpb.Struct
	withPreferredEndpoints  []string
	withSyncIntervalSeconds int32
	withIpAddresses         []string
	withDnsNames            []string
	withLimit               int
	withSetIds              []string
	withSecretsHmac         []byte
	withStartPageAfterItem  pagination.Item
	withWorkerFilter        string
	WithReader              db.Reader
	withWriter              db.Writer
}

func getDefaultOptions() options {
	return options{
		withAttributes: &structpb.Struct{},
	}
}

// WithPluginId provides an optional plugin id.
func withPluginId(with string) Option {
	return func(o *options) {
		o.withPluginId = with
	}
}

// WithPublicId provides an optional public id.
func WithPublicId(with string) Option {
	return func(o *options) {
		o.withPublicId = with
	}
}

// WithDescription provides an optional description.
func WithDescription(desc string) Option {
	return func(o *options) {
		o.withDescription = desc
	}
}

// WithName provides an optional name.
func WithName(name string) Option {
	return func(o *options) {
		o.withName = name
	}
}

// WithExternalName provides an optional external name for the plugin host.
func WithExternalName(externalName string) Option {
	return func(o *options) {
		o.withExternalName = externalName
	}
}

// WithAttributes provides an optional attributes field.
func WithAttributes(attrs *structpb.Struct) Option {
	return func(o *options) {
		o.withAttributes = attrs
	}
}

// WithSecrets provides an optional secrets field.
func WithSecrets(secrets *structpb.Struct) Option {
	return func(o *options) {
		o.withSecrets = secrets
	}
}

// WithPreferredEndpoints provides an optional preferred endpoints field.
func WithPreferredEndpoints(with []string) Option {
	return func(o *options) {
		o.withPreferredEndpoints = with
	}
}

// WithSyncIntervalSeconds provides an optional sync interval, in seconds
func WithSyncIntervalSeconds(with int32) Option {
	return func(o *options) {
		o.withSyncIntervalSeconds = with
	}
}

// withIpAddresses provides an optional list of ip addresses.
func withIpAddresses(with []string) Option {
	return func(o *options) {
		o.withIpAddresses = with
	}
}

// withDnsNames provides an optional list of dns names.
func withDnsNames(with []string) Option {
	return func(o *options) {
		o.withDnsNames = with
	}
}

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are
// returned. If WithLimit == 0, then default limits are used for results.
func WithLimit(l int) Option {
	return func(o *options) {
		o.withLimit = l
	}
}

// WithSetIds provides the ability to restrict lookups to particular matching
// sets.
func WithSetIds(with []string) Option {
	return func(o *options) {
		o.withSetIds = with
	}
}

// WithSecretsHmac provides an optional HMAC of secrets. Used for testing.
func WithSecretsHmac(secretsHmac []byte) Option {
	return func(o *options) {
		o.withSecretsHmac = secretsHmac
	}
}

// WithStartPageAfterItem is used to paginate over the results.
// The next page will start after the provided item.
func WithStartPageAfterItem(item pagination.Item) Option {
	return func(o *options) {
		o.withStartPageAfterItem = item
	}
}

// WithWorkerFilter provides an option to set a plugin host catalog worker
// filter.
func WithWorkerFilter(wf string) Option {
	return func(o *options) {
		o.withWorkerFilter = wf
	}
}

// WithReaderWriter is used to share the same database reader
// and writer when executing sql within a transaction.
func WithReaderWriter(r db.Reader, w db.Writer) Option {
	return func(o *options) {
		o.WithReader = r
		o.withWriter = w
	}
}
