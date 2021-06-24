package db

import (
	"fmt"
	"strings"
)

const (
	sentinel        = "\ufffe"
	notAChar        = "\uffff"
	replacementChar = "\ufffd"
)

// Prefix returns s prefixed with the sentinel character '\ufffe'.
// If s is already prefixed with the sentinel character or s is an empty string,
// s is returned unchanged.
func Prefix(s string) string {
	if s == "" || strings.HasPrefix(s, sentinel) {
		return s
	}
	return fmt.Sprintf("%s%s", sentinel, s)
}

// Strip returns s without the leading sentinel character '\ufffe'.
// If s doesn't start with the sentinel character, s is returned unchanged.
func Strip(s string) string {
	return strings.TrimPrefix(s, sentinel)
}

// Sanitize cleans s by replacing all occurrences of the sentinel character '\ufffe'
// as well as '\uffff' (not a character) with the replacement character '\ufffd'.
// Sanitize should be called before calling Prefix and before a database insert occurs.
func Sanitize(s string) string {
	s = strings.Replace(s, sentinel, replacementChar, -1)
	return strings.Replace(s, notAChar, replacementChar, -1)
}
