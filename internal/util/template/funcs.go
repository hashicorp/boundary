// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package template

import "strings"

// truncateFrom will truncate a string after the first encounter of sep; sep is
// elided. This is a passthrough to strings.Cut with only the first return
// value.
func truncateFrom(str, sep string) string {
	before, _, _ := strings.Cut(str, sep)
	return before
}

// coalesce will return the first non-empty string in the list of strings, and
// an empty string if all parameters are empty.
func coalesce(vals ...string) string {
	for _, val := range vals {
		if val != "" {
			return val
		}
	}
	return ""
}
