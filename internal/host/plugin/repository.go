// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package plugin provides a plugin host catalog, and plugin host set resource
// which are used to interact with a host plugin as well as a repository to
// perform CRUDL and custom actions on these resources.
package plugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	apihc "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

var pluginClientFactoryFn = pluginClientFactory

// A Repository stores and retrieves the persistent types in the plugin
// package. It is not safe to use a repository concurrently.
type Repository struct {
	reader    db.Reader
	writer    db.Writer
	kms       *kms.Kms
	scheduler *scheduler.Scheduler

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
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, sched *scheduler.Scheduler, plgm map[string]plgpb.HostPluginServiceClient, opt ...host.Option) (*Repository, error) {
	const op = "plugin.NewRepository"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "db.Writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "kms")
	case sched == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "scheduler")
	case plgm == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "plgm")
	}

	opts, err := host.GetOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
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
		scheduler:    sched,
		plugins:      plgs,
		defaultLimit: opts.WithLimit,
	}, nil
}

func pluginClientFactory(ctx context.Context, hc *apihc.HostCatalog, controllerClients map[string]plgpb.HostPluginServiceClient) (plgpb.HostPluginServiceClient, error) {
	const op = "plugin.getPluginClient"
	if hc == nil {
		return nil, errors.New(ctx, errors.Internal, op, "host catalog object not present")
	}

	cl, ok := controllerClients[hc.GetPluginId()]
	if !ok || cl == nil {
		return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("controller plugin %q not available", hc.GetPluginId()))
	}

	return cl, nil
}
