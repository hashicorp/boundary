// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"bytes"
	"io"
)

const (
	compressionSize = 1
)

// Compression is used to identify the compression used for the data in chunks.
type Compression uint8

// Supported compression methods.
const (
	NoCompression Compression = iota
	GzipCompression
)

func (c Compression) String() string {
	switch c {
	case NoCompression:
		return "no compression"
	case GzipCompression:
		return "gzip"
	default:
		return "unknown compression"
	}
}

// ValidCompression checks if a given Compression is valid.
func ValidCompression(c Compression) bool {
	switch c {
	case NoCompression, GzipCompression:
		return true
	}
	return false
}

type nullCompressionWriter struct {
	*bytes.Buffer
}

func (w *nullCompressionWriter) Close() error {
	return nil
}

func newNullCompressionWriter(b *bytes.Buffer) io.WriteCloser {
	return &nullCompressionWriter{Buffer: b}
}
