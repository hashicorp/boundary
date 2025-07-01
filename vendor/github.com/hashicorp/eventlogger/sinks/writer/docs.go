// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package writer implements Sink which writes the []byte respresentation of an
// Event to an io.Writer as a string.  Sink allows you to define sinks for any
// io.Writer which includes os.Stdout and os.Stderr
package writer
