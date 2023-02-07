// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package event

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_SysEvent_EventType(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		e := sysEvent{}
		require.Equal(t, string(SystemType), e.EventType())
	})
}
