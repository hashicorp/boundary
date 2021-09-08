package authmethods

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthenticateResultMarshaling(t *testing.T) {
	rawJson := []byte(`{"attributes":{"key":"value"},"command":"foo"}`)
	a := new(AuthenticateResult)
	require.NoError(t, json.Unmarshal(rawJson, a))

	exp := &AuthenticateResult{
		Command: "foo",
		Attributes: map[string]interface{}{
			"key": "value",
		},
		attributesRaw: json.RawMessage(`{"key":"value"}`),
	}

	require.Equal(t, exp, a)

	mBytes, err := json.Marshal(exp)
	require.NoError(t, err)
	require.Equal(t, rawJson, mBytes)
}
