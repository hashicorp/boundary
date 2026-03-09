// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

/*
This package includes a set of tests that run in parallel.
A test should only be added to this package if it can be
completely isolated from other tests that currently exist
in this package. If a test is consistently failing due to
not having an isolated environment, it should be moved to
the adjacent "sequential" package.
*/

package parallel
