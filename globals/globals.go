// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package globals

import "time"

const (
	TcpProxyV1     = "boundary-tcp-proxy-v1"
	ServiceTokenV1 = "s1"

	AnyAuthenticatedUserId = "u_auth"
	AnonymousUserId        = "u_anon"
	RecoveryUserId         = "u_recovery"

	MinimumSupportedPostgresVersion = "12"

	GrantScopeThis        = "this"
	GrantScopeChildren    = "children"
	GrantScopeDescendants = "descendants"
)

type (
	ContextMaxRequestSizeType      struct{}
	ContextOriginalRequestPathType struct{}
	ContextAuthTokenPublicIdType   struct{}
)

var (
	// DefaultMaxRequestDuration is the amount of time we'll wait for a request
	DefaultMaxRequestDuration = 90 * time.Second

	// DefaultMaxRequestSize is the maximum size of a request we allow by default
	DefaultMaxRequestSize = int64(1024 * 1024)

	// DefaultMaxPageSize is the maximum list page size allowed if not set in the config.
	DefaultMaxPageSize = 1000

	// RefreshReadLookbackDuration is used to account for database state mutations
	// missed due to concurrent transactions.
	RefreshReadLookbackDuration = 30 * time.Second

	// ContextMaxRequestSizeTypeKey is a value to keep linters from complaining
	// about clashing string identifiers
	ContextMaxRequestSizeTypeKey ContextMaxRequestSizeType

	// ContextAuthTokenPublicIdKey is a value to keep linters from complaining
	// about clashing string identifiers
	ContextAuthTokenPublicIdKey ContextAuthTokenPublicIdType

	// ContextOriginalRequestPathTypeKey is a value to keep linters from complaining
	// about clashing string identifiers
	ContextOriginalRequestPathTypeKey ContextOriginalRequestPathType

	// RecoveryTokenValidityPeriod is exported so we can modify it in tests if
	// we want
	RecoveryTokenValidityPeriod = 5 * time.Minute

	// WorkerAuthNonceValidityPeriod is exported so we can modify it in tests if
	// we want
	WorkerAuthNonceValidityPeriod = 2 * time.Minute
)
