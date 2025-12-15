// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package static provides a host, a host catalog, and a host set suitable
// for hosts with a static address.
//
// A host catalog contains a collection of hosts with static addresses.
// These hosts can be grouped into host sets allowing them to be used in a
// target. Hosts and host sets are owned by a single host catalog. If a
// host catalog is deleted, all hosts and host sets owned by it are also
// deleted. A host set contains references to zero or more hosts but does
// not own them. Deleting a host set does not effect any of the hosts it
// referenced. A host set can only reference hosts from the host catalog
// that owns it. Host addresses must be unique within a host catalog.
//
// # Repository
//
// A repository provides methods for creating, updating, retrieving, and
// deleting host catalogs, host sets, and hosts. A new repository should be
// created for each transaction. For example:
//
//	var wrapper wrapping.Wrapper
//	... init wrapper...
//
//	// db implements both the reader and writer interfaces.
//	db, _ := db.Open(db.Postgres, url)
//
//	var repo *static.Repository
//
//	repo, _ = static.NewRepository(db, db, wrapper)
//	catalog, _ := repo.LookupCatalog(ctx, catalogId)
//
//	catalog.Name = "new name"
//
//	repo, _ = static.NewRepository(db, db, wrapper)
//	catalog, _ := repo.UpdateCatalog(ctx, catalog, []string{"Name"})
package static
