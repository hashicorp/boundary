// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleHighLevelShortcuts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		in         []string
		out        []string
		expRunOpts bool
	}{
		{
			name: "zero length",
		},
		{
			name: "one length",
			in:   []string{"foo"},
			out:  []string{"foo"},
		},
		{
			name: "not a match",
			in:   []string{"foo", "bar"},
			out:  []string{"foo", "bar"},
		},
		{
			name: "unhandled prefix",
			in:   []string{"read", "bar"},
			out:  []string{"read", "bar"},
		},
		{
			name:       "handled read",
			in:         []string{"read", "hst_1234567890"},
			out:        []string{"hosts", "read"},
			expRunOpts: true,
		},
		{
			name:       "handled delete",
			in:         []string{"delete", "clvlt_1234567890"},
			out:        []string{"credential-libraries", "delete"},
			expRunOpts: true,
		},
		{
			name:       "handled update",
			in:         []string{"update", "g_1234567890"},
			out:        []string{"groups", "update"},
			expRunOpts: true,
		},
		{
			name:       "handled subtype update",
			in:         []string{"update", "credspk_1234567890"},
			out:        []string{"credentials", "update", "ssh-private-key"},
			expRunOpts: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var runOpts RunOptions
			out := handleHighLevelShortcuts(tc.in, &runOpts)
			assert.EqualValues(t, tc.out, out)
			if tc.expRunOpts {
				assert.Equal(t, tc.in[1], runOpts.ImplicitId)
			}
		})
	}
}
