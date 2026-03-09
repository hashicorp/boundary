// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package credentials

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseUsernameDomain tests the ParseUsernameDomain function with various cases.
func TestParseUsernameDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		username         string
		domain           string
		expectedUsername string
		expectedDomain   string
		expectError      bool
		expectErrorStr   string
	}{
		{
			name:             "Empty username and domain",
			username:         "",
			domain:           "",
			expectedUsername: "",
			expectedDomain:   "",
			expectError:      false,
		},
		{
			name:             "Username without domain",
			username:         "user",
			domain:           "",
			expectedUsername: "user",
			expectedDomain:   "",
			expectError:      false,
		},
		{
			name:             "Username and domain",
			username:         "user",
			domain:           "domain",
			expectedUsername: "user",
			expectedDomain:   "domain",
			expectError:      false,
		},
		{
			name:             "Empty username with domain",
			username:         "",
			domain:           "domain",
			expectedUsername: "",
			expectedDomain:   "domain",
			expectError:      false,
		},
		{
			name:             "Username with @domain",
			username:         "user@domain",
			domain:           "",
			expectedUsername: "user",
			expectedDomain:   "domain",
			expectError:      false,
		},
		{
			name:             "Domain\\username format",
			username:         "domain\\user",
			domain:           "",
			expectedUsername: "user",
			expectedDomain:   "domain",
			expectError:      false,
		},
		{
			name:             "Conflicting with username@domain and domain",
			username:         "user@domain",
			domain:           "domain2",
			expectedUsername: "",
			expectedDomain:   "",
			expectError:      true,
			expectErrorStr:   "username and domain cannot be provided together with a username in the format of username@domain or domain\\username",
		},
		{
			name:             "Conflicting with domain\\username and domain",
			username:         "domain\\user",
			domain:           "domain2",
			expectedUsername: "",
			expectedDomain:   "",
			expectError:      true,
			expectErrorStr:   "username and domain cannot be provided together with a username in the format of username@domain or domain\\username",
		},
		{
			name:             "Multiple '@'",
			username:         "user@domain@domain",
			domain:           "",
			expectedUsername: "",
			expectedDomain:   "",
			expectError:      true,
			expectErrorStr:   "invalid format, more than one '@' found",
		},
		{
			name:             "Multiple '\\'",
			username:         "domain\\domain\\user",
			domain:           "",
			expectedUsername: "",
			expectedDomain:   "",
			expectError:      true,
			expectErrorStr:   "invalid format, more than one '\\' found",
		},
		{
			name:             "Mixing '@' and '\\'",
			username:         "domain\\user@domain.com",
			domain:           "",
			expectedUsername: "",
			expectedDomain:   "",
			expectError:      true,
			expectErrorStr:   "invalid format, both '@' and '\\' found",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			username, domain, err := ParseUsernameDomain(test.username, test.domain)
			if test.expectError {
				require.ErrorContains(t, err, test.expectErrorStr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.expectedUsername, username)
			require.Equal(t, test.expectedDomain, domain)
		})
	}
}
