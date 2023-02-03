// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package event

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newId(t *testing.T) {
	t.Run("basics", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		got, err := NewId("pre")
		require.NoError(err)
		assert.True(strings.HasPrefix(got, "pre"))
	})
}
