// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

/*
This package includes a set of tests that run sequentially.
A test should be added to this package if it needs to be completely
isolated from other tests. Newly added tests should not enable the
testing parallel option. Please include a comment in the unit test
that explains why the test must be ran sequentially. Tests that can
be ran in parallel should be moved to the adjacent "parallel" package.
*/

package sequential
