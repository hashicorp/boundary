// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// CreatePlugin inserts p into the repository and returns a new
// Plugin containing the plugin's PublicId. p is not changed. p must
// contain a valid ScopeID. p must not contain a PublicId. The PublicId is
// generated and assigned by this method, unless supplied by WithPublicId
//
// Both p.Name and p.Description are optional. If p.Name is set, it must be
// unique within p.ScopeID.
//
// p.CreateTime, p.UpdateTime, and p.Version are ignored and populated on creation.
//
// Supported options: WithPublicId
func (r *Repository) CreatePlugin(ctx context.Context, p *Plugin, opt ...Option) (*Plugin, error) {
	const op = "plugin.(Repository).CreatePlugin"
	switch {
	case p == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil Plugin")
	case p.Plugin == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil embedded Plugin")
	case p.ScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	case p.ScopeId != scope.Global.String():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "scope id is not 'global'")
	case p.PublicId != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	p = p.clone()

	opts := GetOpts(opt...)

	p.PublicId = opts.withPublicId
	if p.PublicId == "" {
		var err error
		p.PublicId, err = newPluginId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, p.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	metadata := newPluginMetadata(p, oplog.OpType_OP_TYPE_CREATE)

	var newPlugin *Plugin
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newPlugin = p.clone()
			err := w.Create(
				ctx,
				newPlugin,
				db.WithOplog(oplogWrapper, metadata),
			)
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in scope: %s: name %s already exists", p.ScopeId, p.Name)))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in scope: %s", p.ScopeId)))
	}
	return newPlugin, nil
}

// LookupPlugin returns the Plugin for id. Returns nil, nil if no
// Plugin is found for id.
func (r *Repository) LookupPlugin(ctx context.Context, id string, _ ...Option) (*Plugin, error) {
	const op = "plugin.(Repository).LookupPlugin"
	if id == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	c := allocPlugin()
	c.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, c); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", id)))
	}
	return c, nil
}

// LookupPluginByName returns the Plugin for a given name. Returns nil, nil if no
// Plugin is found with that plugin name.
func (r *Repository) LookupPluginByName(ctx context.Context, name string, _ ...Option) (*Plugin, error) {
	const op = "plugin.(Repository).LookupPluginByName"
	if name == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no plugin name")
	}
	p := allocPlugin()

	if err := r.reader.LookupWhere(ctx, p, "name=?", []any{name}); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", name)))
	}
	return p, nil
}

// ListPlugins returns a slice of Plugins for the scope IDs. WithLimit is the only option supported.
func (r *Repository) ListPlugins(ctx context.Context, scopeIds []string, opt ...Option) ([]*Plugin, error) {
	const op = "plugin.(Repository).ListPlugins"
	if len(scopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	opts := GetOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var plugins []*Plugin
	err := r.reader.SearchWhere(ctx, &plugins, "scope_id in (?)", []any{scopeIds}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return plugins, nil
}

// AddSupportFlag adds a flag in the database for the current plugin to specify that it is capable
// of that type's functions
func (r *Repository) AddSupportFlag(ctx context.Context, plugin *Plugin, flag PluginType) error {
	const op = "plugin.(Repository).AddSupportFlag"

	var p pluginSupportedTable

	switch flag {
	case PluginTypeHost:
		p = &pluginHostSupported{
			PublicId: plugin.GetPublicId(),
		}
	case PluginTypeStorage:
		p = &pluginStorageSupported{
			PublicId: plugin.GetPublicId(),
		}
	default:
		return errors.New(ctx, errors.InvalidParameter, op, "plugin type does not exist")
	}

	if err := r.writer.Create(ctx, p, db.WithOnConflict(
		&db.OnConflict{
			Target: db.Columns{"public_id"},
			Action: db.DoNothing(true),
		},
	)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}
