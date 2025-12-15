// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

/*
Globals, in the traditional sense, are usually bad. But there are some
situations where we want either consts or known values that are constant per
invocation but invocation may be in various places, such as a test or via CLI,
and placing such a value in any given package leads to import issues. So think
of this package as "freeing us from circular dependency hell".

This package provides _exported_ globals that might reasonably be used by API
users, Terraform, etc. A separate package, under internal/intglobals, provides
globals that perform a similar function but are only meant for internal use.

There is no race checking; these values should only ever be set at startup of
Boundary or a test, but available to reference from anywhere.
*/

package globals
