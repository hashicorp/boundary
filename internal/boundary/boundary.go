// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


// Package boundary contains global interfaces and other definitions that
// define the Boundary domain.
package boundary

import (
	"github.com/hashicorp/boundary/internal/db/timestamp"
)

// An Entity is an object distinguished by its identity, rather than its
// attributes. It can contain value objects and other entities.
type Entity interface {
	GetPublicId() string
}

// An Aggregate is an entity that is the root of a transactional
// consistency boundary.
type Aggregate interface {
	Entity
	GetVersion() uint32
	GetCreateTime() *timestamp.Timestamp
	GetUpdateTime() *timestamp.Timestamp
}

// A Resource is an aggregate with a name and description.
type Resource interface {
	Aggregate
	GetName() string
	GetDescription() string
}

// AuthzProtectedEntity is used by some functions (primarily
// scopeids.AuthzProtectedEntityProvider-conforming implementations) to deliver
// some common information necessary for calculating authz.
type AuthzProtectedEntity interface {
	Entity
	GetProjectId() string
	GetUserId() string
}
