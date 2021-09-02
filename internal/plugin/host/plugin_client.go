package host

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/plugin/builtin/testing/testhostplugin"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// embeddedPluginClients contains a factory to our embedded plugins.
// These plugins are loaded directly and linked in the Boundary
// binary, instead of being installed from the embedded filesystem.
var embeddedPluginClients = map[string]func() plugin.HostPluginServiceClient{
	// "aws": awsplugin.NewClient,
	"testing": testhostplugin.NewClient,
}

// PluginManager is a helper for loading and managing host plugins.
type PluginManager struct {
	repo *Repository
}

// NewPluginManager takes in a repo and returns a PluginManager.
func NewPluginManager(ctx context.Context, repo *Repository, _ ...Option) (*PluginManager, error) {
	const op = "host.NewPluginManager"
	if repo == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing underlying repo")
	}

	return &PluginManager{
		repo: repo,
	}, nil
}

// LoadPlugin loads the plugin supplied by id. This fully
// instantiates the plugin, including starting any processes if
// necessary, and returning the client for the particular plugin.
//
// TODO: This feature is under heavy development.
func (m *PluginManager) LoadPlugin(ctx context.Context, id string) (plugin.HostPluginServiceClient, error) {
	const op = "host.(PluginManager).LoadPlugin"
	if id == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no plugin id")
	}

	// Attempt to look up the plugin in the database.
	plugin, err := m.repo.LookupPlugin(ctx, id)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("plugin lookup failed"))
	}

	if plugin == nil {
		return nil, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("could not find plugin for id %q", id))
	}

	// This is a shim to embedded instantiation of the plugin client.
	// We currently use a static list of plugins which link directly to
	// the list of built-in plugins. TODO: replace this with the
	// full-on go-plugin launcher once it is ready.
	clientFunc, ok := embeddedPluginClients[plugin.PluginName]
	if !ok {
		// TODO: We may need a new error class for plugin management.
		// Lookup errors here and other instantiation errors after this
		// could be indicative of deeper system errors, ie: installation
		// errors, execution errors, etc.
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("plugin with name %q is not an embedded plugin", plugin.PluginName))
	}

	return clientFunc(), nil
}
