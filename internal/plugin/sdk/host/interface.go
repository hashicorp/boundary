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
	// The following hook functions run create, update, and delete
	// functionality for host catalogs.
	//
	// These hooks take the catalog as it exists in the respective
	// request (along with any secrets), with both the old and new
	// state provided in update. These hooks are designed to provide a
	// way for the provider to both do validation and possibly return a
	// persisted state. The returned persisted state is encrypted.
	//
	// Any error returned will cause the state to not be persisted and
	// an error returned to the caller.
	OnCreateCatalog(
		ctx context.Context,
		cat proto.HostCatalog,
	) (proto.HostCatalogPersisted, error)
	OnUpdateCatalog(
		ctx context.Context,
		oldCat, newCat proto.HostCatalog,
		persisted proto.HostCatalogPersisted,
	) (proto.HostCatalogPersisted, error)
	OnDeleteCatalog(
		ctx context.Context,
		cat proto.HostCatalog,
		persisted proto.HostCatalogPersisted,
	) error

	// The following hook functions run create, update, and delete
	// functionality for host sets.
	//
	// These hooks take the both the parent host catalog (along with
	// any secrets), and the host set as it exists in the respective
	// request, with both the old and new sets provided in update. The
	// persisted state from the parent host catalog resource is also
	// sent.
	OnCreateSet(
		ctx context.Context,
		cat proto.HostCatalog,
		set proto.HostSet,
		persisted proto.HostCatalogPersisted,
	) error
	OnUpdateSet(
		ctx context.Context,
		cat proto.HostCatalog,
		oldSet, newSet proto.HostSet,
		persisted proto.HostCatalogPersisted,
	) error
	OnDeleteSet(
		ctx context.Context,
		cat proto.HostCatalog,
		set proto.HostSet,
		persisted proto.HostCatalogPersisted,
	) error

	// ListHosts looks up all the hosts in the provided host sets.
	//
	// The plugin is responsible for performing the necessary cloud API
	// calls and translation of the data expected by Boundary for the
	// response to this call.
	ListHosts(
		ctx context.Context,
		cat proto.HostCatalog,
		sets []proto.HostSet,
		persisted proto.HostCatalogPersisted,
	) ([]proto.Host, error)
}
