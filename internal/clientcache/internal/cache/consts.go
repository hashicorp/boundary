// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

/*
Package cache contains the domain logic for the client cache.
*/
package cache

const (
	// defaultLimitedResultSetSize is the default number of results to
	// return when limiting
	defaultLimitedResultSetSize = 250

	// unlimitedMaxResultSetSize is the value to use when we want to return all
	// results
	unlimitedMaxResultSetSize = -1
)
