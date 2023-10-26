// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/util"
)

// PluginCatalogRepository defines the interface expected
// to gather information about plugin host catalogs.
type PluginCatalogRepository interface {
	EstimatedCatalogCount(context.Context) (int, error)
	ListDeletedCatalogIds(context.Context, time.Time, ...Option) ([]string, error)
	ListCatalogs(context.Context, []string, ...Option) ([]Catalog, []*plugin.Plugin, error)
}

// StaticCatalogRepository defines the interface expected
// to gather information about static host catalogs.
type StaticCatalogRepository interface {
	EstimatedCatalogCount(context.Context) (int, error)
	ListDeletedCatalogIds(context.Context, time.Time, ...Option) ([]string, error)
	ListCatalogs(context.Context, []string, ...Option) ([]Catalog, error)
}

// CatalogService coordinates calls across different subtype repositories
// to gather information about all host catalogs.
type CatalogService struct {
	pluginRepo PluginCatalogRepository
	staticRepo StaticCatalogRepository
	writer     db.Writer
}

// NewCatalogService returns a new host catalog service.
func NewCatalogService(ctx context.Context, writer db.Writer, pluginRepo PluginCatalogRepository, staticRepo StaticCatalogRepository) (*CatalogService, error) {
	const op = "host.NewCatalogService"
	switch {
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(pluginRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing plugin repo")
	case util.IsNil(staticRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing static repo")
	}
	return &CatalogService{
		staticRepo: staticRepo,
		pluginRepo: pluginRepo,
		writer:     writer,
	}, nil
}
