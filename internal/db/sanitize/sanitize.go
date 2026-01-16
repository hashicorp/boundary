// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sanitize

import (
	"unicode"

	"github.com/hashicorp/boundary/internal/db/sentinel"
)

// String sanitizes s by replacing all invalid unicode characters as well as the sentinel
// start character U+FFFE and sentinel end character U+FFFF with the Unicode
// replacement character U+FFFD.
//
// According to the Unicode standard: "If a noncharacter is received in open interchange,
// an application is not required to interpret it in any way. It is good practice, however,
// to recognize it as a noncharacter and to take appropriate action, such as replacing it
// with U+FFFD replacement character."
// See https://www.unicode.org/versions/Unicode13.0.0/ch23.pdf#G12612.
func String(s string) string {
	out := make([]rune, 0, len(s))

	// For a string, the range clause will return the index and the rune at the index of
	// the string. If the iteration encounters an invalid UTF-8 sequence, the rune value
	// returned will be 0xFFFD, the Unicode replacement character.
	// See https://golang.org/ref/spec#For_statements.
	for _, r := range s {
		switch r {
		case sentinel.Start, sentinel.End:
			// The range clause does not replace the sentinel start and end characters.
			out = append(out, unicode.ReplacementChar)
		default:
			out = append(out, r)
		}
	}
	return string(out)
}
