// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/stretchr/testify/assert"
)

func TestMagic(t *testing.T) {
	assert.Equal(t, string(bsr.Magic), "\x89BSR\r\n\x1a\n")
	assert.Equal(t, bsr.Magic.Bytes(), []byte("\x89BSR\r\n\x1a\n"))
}

func TestReadMagic(t *testing.T) {
	cases := []struct {
		name string
		r    io.Reader
		want error
	}{
		{
			"valid",
			bytes.NewBuffer([]byte(bsr.Magic)),
			nil,
		},
		{
			"nil-reader",
			nil,
			errors.New("bsr.ReadMagic: reader is nil: invalid parameter"),
		},
		{
			"not-enough-chars",
			bytes.NewBuffer([]byte(bsr.Magic)[:len(bsr.Magic)-1]),
			errors.New("bsr.ReadMagic: unexpected EOF"),
		},
		{
			"not-magic",
			bytes.NewBuffer([]byte("notthemagic")),
			errors.New("bsr.ReadMagic: invalid magic string"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bsr.ReadMagic(tc.r)
			if tc.want == nil {
				assert.NoError(t, got)
				return
			}
			assert.EqualError(t, got, tc.want.Error())
		})
	}
}
