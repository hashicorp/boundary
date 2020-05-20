package handlers

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNotFoundErrorf(t *testing.T) {
	err := NotFoundErrorf("something")
	apiErr, ok := statusErrorToApiError(err)
	assert.True(t, ok)

	w := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	err = encoder.Encode(apiErr)
	assert.NoError(t, err)
	t.Logf("The results of the json encoding are: %q", w.String())
}
