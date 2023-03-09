// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package globals

// This set of consts is intended to be a place to collect commonly-used
// prefixes. This can avoid some cross-package dependency issues. Unlike the
// top-level globals package, these are not currently meant to be available to
// clients or test writers.

const (
	// AuthTokenPrefix is the prefix for auth tokens
	AuthTokenPrefix = "at"

	// OldPasswordAccountPrefix is the previously-used account prefix
	OldPasswordAccountPrefix = "apw"
	// NewPasswordAccountPrefix is the new account prefix
	NewPasswordAccountPrefix = "acctpw"

	// OidcAuthMethodPrefix defines the prefix for AuthMethod public ids.
	OidcAuthMethodPrefix = "amoidc"
	// OidcAccountPrefix defines the prefix for Account public ids.
	OidcAccountPrefix = "acctoidc"
	// OidcManagedGroupPrefix defines the prefix for ManagedGroup public ids
	// from the OIDC auth method.
	OidcManagedGroupPrefix = "mgoidc"
)
