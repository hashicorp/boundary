// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenSecret_String(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = redactedTokenSecret
		tk := TokenSecret("special secret")
		assert.Equalf(want, tk.String(), "TokenSecret.String() = %v, want %v", tk.String(), want)

		// Verify stringer is called
		s := fmt.Sprintf("%s", tk)
		assert.Equalf(want, s, "TokenSecret.String() = %v, want %v", s, want)
	})
}

func TestTokenSecret_GoString(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = redactedTokenSecret
		tk := TokenSecret("magic secret")
		assert.Equalf(want, tk.GoString(), "TokenSecret.GoString() = %v, want %v", tk.GoString(), want)

		// Verify gostringer is called
		s := fmt.Sprintf("%#v", tk)
		assert.Equalf(want, s, "TokenSecret.GoString() = %v, want %v", s, want)
	})
}

func TestTokenSecret_MarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want, err := json.Marshal([]byte(redactedTokenSecret))
		require.NoError(err)
		tk := TokenSecret("normal secret")
		got, err := tk.MarshalJSON()
		require.NoError(err)
		assert.Equalf(want, got, "TokenSecret.MarshalJSON() = %s, want %s", got, want)
	})
	t.Run("within-struct", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want := fmt.Sprintf(`%s`, redactedTokenSecret)

		type secretContainer struct {
			S TokenSecret
			B []byte
		}
		testB := []byte("my secret")
		secret := secretContainer{S: testB, B: testB}

		m, err := json.Marshal(secret)
		require.NoError(err)

		var sec secretContainer
		err = json.Unmarshal(m, &sec)
		require.NoError(err)
		assert.Equal(TokenSecret(want), sec.S)
		assert.Equal(testB, sec.B)
	})
}

func TestKeySecret_String(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = redactedKeySecret
		tk := KeySecret("our secret")
		assert.Equalf(want, tk.String(), "KeySecret.String() = %v, want %v", tk.String(), want)

		// Verify stringer is called
		s := fmt.Sprintf("%s", tk)
		assert.Equalf(want, s, "KeySecret.String() = %v, want %v", s, want)
	})
}

func TestKeySecret_GoString(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = redactedKeySecret
		tk := KeySecret("private secret")
		assert.Equalf(want, tk.GoString(), "KeySecret.GoString() = %v, want %v", tk.GoString(), want)

		// Verify gostringer is called
		s := fmt.Sprintf("%#v", tk)
		assert.Equalf(want, s, "KeySecret.GoString() = %v, want %v", s, want)
	})
}

func TestKeySecret_MarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want, err := json.Marshal([]byte(redactedKeySecret))
		require.NoError(err)
		tk := KeySecret("hidden secret")
		got, err := tk.MarshalJSON()
		require.NoError(err)
		assert.Equalf(want, got, "KeySecret.MarshalJSON() = %s, want %s", got, want)
	})
	t.Run("within-struct", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want := fmt.Sprintf(`%s`, redactedKeySecret)

		type secretContainer struct {
			S KeySecret
			B []byte
		}
		testB := []byte("secure secret")
		secret := secretContainer{S: testB, B: testB}

		m, err := json.Marshal(secret)
		require.NoError(err)

		var sec secretContainer
		err = json.Unmarshal(m, &sec)
		require.NoError(err)
		assert.Equal(KeySecret(want), sec.S)
		assert.Equal(testB, sec.B)
	})
}
