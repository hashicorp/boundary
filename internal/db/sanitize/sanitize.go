package sanitize

import (
	"unicode"

	"github.com/hashicorp/boundary/internal/db/sentinel"
)

// String sanitizes s by replacing all invalid unicode characters including the sentinel
// start character '\ufffe' and sentinel end character '\uffff' with the unicode
// replacement character '\ufffd'.
func String(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch r {
		case sentinel.Start, sentinel.End:
			out = append(out, unicode.ReplacementChar)
		default:
			out = append(out, r)
		}
	}
	return string(out)
}
