// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNullCompressionWriter(t *testing.T) {
	var buf bytes.Buffer
	var compressor io.WriteCloser

	expect := []byte("uncompressed data")
	compressor = newNullCompressionWriter(&buf)

	wrote, err := compressor.Write(expect)
	require.NoError(t, err)
	assert.Equal(t, len(expect), wrote)

	err = compressor.Close()
	require.NoError(t, err)

	assert.Equal(t, expect, buf.Bytes())
}
