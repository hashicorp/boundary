// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package gated implements a Filter that provides the ability to buffer events
// based on their IDs until an event is flushed.  When an individual gated event
// is flushed, the filter will build and emit a composite event for the flushed
// event using it's ID to identify all the related gated events up until that
// point in time.
package gated
