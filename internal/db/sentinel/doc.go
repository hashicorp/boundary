// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package sentinel allows for the use of Unicode non-characters to distinguish between
// Boundary defined sentinels and values provided by external systems.
//
// All sentinel values are prefixed with the sentinel start character U+FFFE and suffixed
// with the sentinel end character U+FFFF. Any string that starts with U+FFFE and ends with
// U+FFFF is a valid sentinel and reserved for use within Boundary.
//
// U+FFFE and U+FFFF are special non-characters reserved for internal use in the Unicode
// standard.
// See https://www.unicode.org/versions/Unicode13.0.0/ch23.pdf#G12612.
package sentinel
