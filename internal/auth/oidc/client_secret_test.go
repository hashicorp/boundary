// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientSecret_String(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = redactedClientSecret
		tk := ClientSecret("super secret token")
		assert.Equalf(want, tk.String(), "ClientSecret.String() = %v, want %v", tk.String(), want)

		// Verify stringer is called
		s := fmt.Sprintf("%#v", tk)
		assert.Equalf(want, s, "ClientSecret.String() = %v, want %v", s, want)
	})
}

func TestClientSecret_GoString(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = redactedClientSecret
		tk := ClientSecret("super secret token")
		assert.Equalf(want, tk.GoString(), "ClientSecret.GoString() = %v, want %v", tk.GoString(), want)

		// Verify gostringer is called
		s := fmt.Sprintf("%#v", tk)
		assert.Equalf(want, s, "ClientSecret.GoString() = %v, want %v", s, want)
	})
}

func TestClientSecret_MarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want := fmt.Sprintf(`"%s"`, redactedClientSecret)
		tk := ClientSecret("super secret token")
		got, err := tk.MarshalJSON()
		require.NoError(err)
		assert.Equalf([]byte(want), got, "ClientSecret.MarshalJSON() = %s, want %s", got, want)
	})
}
