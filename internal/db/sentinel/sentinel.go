package sentinel

import (
	"strings"
)

const (
	sentinelStart   = "\ufffe"
	sentinelEnd     = "\uffff"
	replacementChar = "\ufffd"
)

// Is returns true if s is a valid sentinel.
func Is(s string) bool {
	if s == "" {
		// empty string is not a valid sentinel
		return false
	}
	if !strings.HasPrefix(s, sentinelStart) {
		return false
	}
	if !strings.HasSuffix(s, sentinelEnd) {
		return false
	}
	// Trim all leading sentinel start characters and spaces
	s = strings.TrimLeft(s, sentinelStart+" ")

	// Trim all trailing sentinel end characters
	s = strings.TrimRight(s, sentinelEnd)
	return len(s) > 0
}

// Sanitize cleans s by replacing all occurrences of the sentinel start character '\ufffe'
// as well as the sentinel end character '\uffff' with the replacement character '\ufffd'.
// Sanitize should be called before a database insert occurs.
func Sanitize(s string) string {
	if s == "" {
		return s
	}
	s = strings.Replace(s, sentinelStart, replacementChar, -1)
	return strings.Replace(s, sentinelEnd, replacementChar, -1)
}
