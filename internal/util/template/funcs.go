package template

import "strings"

// truncateFrom will truncate a string after the first encounter of sep; sep is
// elided. This is a passthrough to strings.Cut with only the first return
// value.
func truncateFrom(str, sep string) string {
	before, _, _ := strings.Cut(str, sep)
	return before
}
