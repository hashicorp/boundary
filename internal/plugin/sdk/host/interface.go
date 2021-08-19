// Package host provides the interfaces and functionality for host
// plugins. Host plugins provide functionality for dynamic host
// catalogs and host sets.
package host

import (
	"context"

	"github.com/hashicorp/boundary/internal/plugin/sdk/proto"
)

// HostPlugin describes the interface for host plugins.
type HostPlugin interface {
	// OnCreateCatalog is a hook that runs when a host catalog is
	// created. It takes a context and the host catalog to create,
	// which may contain (optional) secret data to help authenticate
	// the request against a cloud API.
	//
	// The plugin may return optional state data to be persisted and
	// at-rest encrypted. This should be used to store authentication
	// data and other necessary configuration to be used in later hooks
	// and lookup calls. If an error is returned, data persistence is
	// aborted.
	OnCreateCatalog(ctx context.Context, cat proto.HostCatalog) (proto.HostCatalogPersisted, error)

	// OnUpdateCatalog is a hook that runs when a host catalog is
	// updated. It takes a context and the host catalog to update, both
	// in its pre-update, and post-update form. The post-update catalog
	// may contain (optional) secret data. The existing persisted state
	// is also included, decrypted and ready for use.
	//
	// The plugin should return the updated persisted data - it's
	// important that this be returned if it existed previously, as the
	// returned data overwrites the previously existing copy. If an
	// error is returned, the update of the persisted data is aborted.
	OnUpdateCatalog(ctx context.Context, oldCat, newCat proto.HostCatalog, persisted proto.HostCatalogPersisted) (proto.HostCatalogPersisted, error)

	// OnDeleteCatalog is a hook that runs when a host catalog is
	// deleted. It takes a context and the host catalog to delete.
	// Persisted state is also included to allow for any necessary
	// cleanup functions to run against a cloud API.
	//
	// An error returned by this function will abort the delete.
	// Plugins should not return errors if the error is a no-op
	// (example: attempting to clean up already removed resources).
	OnDeleteCatalog(ctx context.Context, cat proto.HostCatalog, persisted proto.HostCatalogPersisted) error

	// OnCreateSet is a hook that runs when a host set is
	// created. It takes a context, the set's parent catalog, the new
	// set to create, and the decrypted persisted state from the host
	// catalog.
	//
	// The plugin should return an error if the creation of the host
	// set should be blocked for any reason.
	OnCreateSet(ctx context.Context, cat proto.HostCatalog, set proto.HostSet, persisted proto.HostCatalogPersisted) error

	// OnUpdateSet is a hook that runs when a host set is updated. It
	// takes a context, the set's parent catalog, the pre-update and
	// post-update copies of the set, and the and the decrypted
	// persisted state from the host catalog.
	//
	// The plugin should return an error if the update of the host set
	// should be blocked for any reason.
	OnUpdateSet(ctx context.Context, cat proto.HostCatalog, oldSet, newSet proto.HostSet, persisted proto.HostCatalogPersisted) error

	// OnDeleteSet is a hook that runs when a host set is deleted. It
	// takes a context, the set's parent catalog, the set itself, and
	// the and the decrypted persisted state from the host catalog.
	//
	// The plugin should return an error if the delete of the host set
	// should be blocked for any reason.
	OnDeleteSet(ctx context.Context, cat proto.HostCatalog, set proto.HostSet, persisted proto.HostCatalogPersisted) error

	// ListHosts looks up all the hosts in the provided host sets. The
	// persisted state is also supplied decrypted from the host catalog
	// to ensure any authentication data necessary to make the request
	// is present.
	//
	// The plugin is responsible for performing the necessary cloud API
	// calls and translation of the data expected by Boundary for the
	// response to this call.
	ListHosts(ctx context.Context, cat proto.HostCatalog, sets []proto.HostSet, persisted proto.HostCatalogPersisted) ([]proto.Host, error)
}
