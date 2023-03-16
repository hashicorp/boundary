// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

const (
	// Magic is the magic string / magic number / file signature used to
	// identify a BSR data file.
	//
	// See: https://en.wikipedia.org/wiki/File_format#Magic_number
	Magic magic = magic("\x89BSR\r\n\x1a\n")

	magicSize = len(Magic)
)

type magic string

// Bytes returns the magic as a []byte.
func (s magic) Bytes() []byte {
	return []byte(s)
}
