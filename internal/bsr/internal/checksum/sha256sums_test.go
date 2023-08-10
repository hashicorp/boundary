// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package checksum_test

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/checksum"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSha256Sums(t *testing.T) {
	cases := []struct {
		name    string
		r       io.Reader
		want    checksum.Sha256Sums
		wantErr error
	}{
		{
			"valid-multi-line-text",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e  file1
7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53  file2
`),
			checksum.Sha256Sums{
				"file1": []byte("ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e"),
				"file2": []byte("7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53"),
			},
			nil,
		},
		{
			"valid-multi-line-binary",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e *file1
7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53 *file2
`),
			checksum.Sha256Sums{
				"file1": []byte("ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e"),
				"file2": []byte("7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53"),
			},
			nil,
		},
		{
			"valid-multi-line-text-and-binary",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e  file1
7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53 *file2
`),
			checksum.Sha256Sums{
				"file1": []byte("ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e"),
				"file2": []byte("7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53"),
			},
			nil,
		},
		{
			"valid-multi-line-binary-and-text",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e *file1
7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53  file2
`),
			checksum.Sha256Sums{
				"file1": []byte("ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e"),
				"file2": []byte("7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53"),
			},
			nil,
		},
		{
			"invalid-single-space",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e file1`),
			nil,
			fmt.Errorf("checksum.LoadSha256Sums: improperly formated line"),
		},
		{
			"invalid-no-file",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e`),
			nil,
			fmt.Errorf("checksum.LoadSha256Sums: improperly formated line"),
		},
		{
			"invalid-no-sum-file",
			strings.NewReader(`file1`),
			nil,
			fmt.Errorf("checksum.LoadSha256Sums: improperly formated line"),
		},
		{
			"invalid-hash-too-short",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00  file1`),
			nil,
			fmt.Errorf("checksum.LoadSha256Sums: improperly formated line"),
		},
		{
			"invalid-hash-too-long",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00ef  file1`),
			nil,
			fmt.Errorf("checksum.LoadSha256Sums: improperly formated line"),
		},
		{
			"invalid-duplicate-file-name",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e  file1
7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53  file1
`),
			nil,
			fmt.Errorf("checksum.LoadSha256Sums: duplicate file"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checksum.LoadSha256Sums(tc.r)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
