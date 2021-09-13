package credential

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPassword_String(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = redactedPassword
		passwd := Password("special secret")
		assert.Equalf(want, passwd.String(), "Password.String() = %v, want %v", passwd.String(), want)

		// Verify stringer is called
		s := fmt.Sprintf("%s", passwd)
		assert.Equalf(want, s, "Password.String() = %v, want %v", s, want)
	})
}

func TestPassword_GoString(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = redactedPassword
		passwd := Password("magic secret")
		assert.Equalf(want, passwd.GoString(), "Password.GoString() = %v, want %v", passwd.GoString(), want)

		// Verify gostringer is called
		s := fmt.Sprintf("%#v", passwd)
		assert.Equalf(want, s, "Password.GoString() = %v, want %v", s, want)
	})
}

func TestPassword_MarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want, err := json.Marshal(redactedPassword)
		require.NoError(err)
		passwd := Password("normal secret")
		got, err := passwd.MarshalJSON()
		require.NoError(err)
		assert.Equalf(want, got, "Password.MarshalJSON() = %s, want %s", got, want)
	})
	t.Run("within-struct", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want := fmt.Sprintf(`%s`, redactedPassword)

		type secretContainer struct {
			P Password
			S string
		}
		testB := "my secret"
		secret := secretContainer{P: Password(testB), S: testB}

		m, err := json.Marshal(secret)
		require.NoError(err)

		var sec secretContainer
		err = json.Unmarshal(m, &sec)
		require.NoError(err)
		assert.Equal(Password(want), sec.P)
		assert.Equal(testB, sec.S)
	})
}

func TestPrivateKey_String(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = redactedPrivateKey
		pk := PrivateKey("special secret")
		assert.Equalf(want, pk.String(), "PrivateKey.String() = %v, want %v", pk.String(), want)

		// Verify stringer is called
		s := fmt.Sprintf("%s", pk)
		assert.Equalf(want, s, "PrivateKey.String() = %v, want %v", s, want)
	})
}

func TestPrivateKey_GoString(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = redactedPrivateKey
		pk := PrivateKey("magic secret")
		assert.Equalf(want, pk.GoString(), "PrivateKey.GoString() = %v, want %v", pk.GoString(), want)

		// Verify gostringer is called
		s := fmt.Sprintf("%#v", pk)
		assert.Equalf(want, s, "PrivateKey.GoString() = %v, want %v", s, want)
	})
}

func TestPrivateKey_MarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want, err := json.Marshal([]byte(redactedPrivateKey))
		require.NoError(err)
		pk := PrivateKey("normal secret")
		got, err := pk.MarshalJSON()
		require.NoError(err)
		assert.Equalf(want, got, "PrivateKey.MarshalJSON() = %s, want %s", got, want)
	})
	t.Run("within-struct", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want := fmt.Sprintf(`%s`, redactedPrivateKey)

		type secretContainer struct {
			S PrivateKey
			B []byte
		}
		testB := []byte("my secret")
		secret := secretContainer{S: testB, B: testB}

		m, err := json.Marshal(secret)
		require.NoError(err)

		var sec secretContainer
		err = json.Unmarshal(m, &sec)
		require.NoError(err)
		assert.Equal(PrivateKey(want), sec.S)
		assert.Equal(testB, sec.B)
	})
}
