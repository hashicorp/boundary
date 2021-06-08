package intglobals

// This set of consts is intended to be a place to collect commonly-used
// prefixes. This can avoid some cross-package dependency issues. Unlike the
// top-level globals package, these are not currently meant to be available to
// clients or test writers.

const (
	// OidcManagedGroupPrefix defines the prefix for ManagedGroup public ids
	// from the OIDC auth method.
	OidcManagedGroupPrefix = "mgoidc"

	// OldPasswordAccountPrefix is the previously-used account prefix
	OldPasswordAccountPrefix = "apw"

	// NewPasswordAccountPrefix is the new account prefix
	NewPasswordAccountPrefix = "acctpw"
)
