// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package credentials

import (
	"fmt"
	"strings"
)

// ParseUsernameDomain parses the username and domain from the given strings.
// It returns the username, domain, and an error if any.
// The username can be in the format of "username", "username@domain", or "domain\username".
func ParseUsernameDomain(username, domain string) (string, string, error) {
	switch {
	case username != "" && domain == "":
		atCount := strings.Count(username, "@")
		if atCount > 1 {
			return "", "", fmt.Errorf("invalid format, more than one '@' found")
		}
		backslashCount := strings.Count(username, "\\")
		if backslashCount > 1 {
			return "", "", fmt.Errorf("invalid format, more than one '\\' found")
		}
		if atCount > 0 && backslashCount > 0 {
			return "", "", fmt.Errorf("invalid format, both '@' and '\\' found")
		}

		// username@domain
		if u, d, ok := strings.Cut(username, "@"); ok {
			return u, d, nil
		}
		// domain\username
		if d, u, ok := strings.Cut(username, "\\"); ok {
			return u, d, nil
		}
	case username != "" && domain != "":
		if strings.Contains(username, "@") || strings.Contains(username, "\\") {
			return "", "", fmt.Errorf("username and domain cannot be provided together with a username in the format of username@domain or domain\\username")
		}
	}

	return username, domain, nil
}
