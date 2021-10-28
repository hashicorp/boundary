// Package plugin provides a plugin host catalog, and plugin host set resource
// which are used to interact with a host plugin as well as a repository to
// perform CRUDL and custom actions on these resources.
package plugin

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/kms"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// A Repository stores and retrieves the persistent types in the plugin
// package. It is not safe to use a repository concurrently.
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// plugins is a map from plugin resource id to host plugin client.
	plugins map[string]plgpb.HostPluginServiceClient
	// defaultLimit provides a default for limiting the number of results
	// returned from the repo
	defaultLimit int
}

// NewRepository creates a new Repository. The returned repository should
// only be used for one transaction and it is not safe for concurrent go
// routines to access it. WithLimit option is used as a repo wide default
// limit applied to all ListX methods.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, plgm map[string]plgpb.HostPluginServiceClient, opt ...host.Option) (*Repository, error) {
	const op = "plugin.NewRepository"
	switch {
	case r == nil:
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "db.Reader")
	case w == nil:
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "db.Writer")
	case kms == nil:
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "kms")
	case plgm == nil:
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "plgm")
	}

	opts, err := host.GetOpts(opt...)
	if err != nil {
		return nil, errors.WrapDeprecated(err, op)
	}
	if opts.WithLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.WithLimit = db.DefaultLimit
	}

	plgs := make(map[string]plgpb.HostPluginServiceClient, len(plgm))
	for k, v := range plgm {
		plgs[k] = v
	}

	return &Repository{
		reader:       r,
		writer:       w,
		kms:          kms,
		plugins:      plgs,
		defaultLimit: opts.WithLimit,
	}, nil
}
