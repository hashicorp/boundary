// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummaryError_MarshalJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "error string",
			in:   "error",
			want: "\"error\"",
		},
		{
			name: "empty string",
			in:   "",
			want: "\"\"",
		},
		{
			name: "empty object",
			in:   `{}`,
			want: "\"{}\"",
		},
		{
			name: "empty object",
			in:   `null`,
			want: "\"null\"",
		},
		{
			name: "key value object",
			in:   `{"message": "failed to load"}`,
			want: "\"{\\\"message\\\": \\\"failed to load\\\"}\"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			summaryErr := bsr.SummaryError{Message: tc.in}

			got, err := summaryErr.MarshalJSON()
			require.NoError(t, err)

			assert.Equal(t, tc.want, string(got))
		})
	}
}

func TestSummaryError_UnmarshalJSON(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{
			name: "error string",
			in:   "error",
			want: "error",
		},
		{
			name: "empty string",
			in:   "",
			want: "",
		},
		{
			name: "empty object",
			in:   `{}`,
			want: "",
		},
		{
			name: "empty object",
			in:   `null`,
			want: "",
		},
		{
			name: "key value object",
			in:   `{"message": "failed to load"}`,
			want: "{\"message\": \"failed to load\"}",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var summaryErr bsr.SummaryError

			input, err := json.Marshal(tc.in)
			require.NoError(t, err)

			err = summaryErr.UnmarshalJSON(input)
			require.NoError(t, err)

			assert.Equal(t, tc.want, summaryErr.Message)
		})
	}
}

func TestBaseSessionSummary_GetErrors(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want error
	}{
		{
			name: "error string",
			in:   errors.New("error"),
			want: errors.New("error"),
		},
		{
			name: "empty string should return nil error",
			in:   errors.New(""),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			summary := bsr.BaseSessionSummary{}
			summary.SetErrors(tc.in)

			got := summary.GetErrors()
			assert.Equal(t, tc.want, got)
		})
	}
}
