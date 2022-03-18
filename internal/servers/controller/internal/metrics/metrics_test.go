package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildRegexFromPath(t *testing.T) {
	p := "/v1/pathsomething/{id}:test-thing"
	r := buildRegexFromPath(p)
	assert.True(t, r.Match([]byte("/v1/pathsomething/a4s_aKsdFh723018djsa:test-thing")))
	assert.False(t, r.Match([]byte("/v1/pathsomething:test-thing")))
	assert.False(t, r.Match([]byte("/v1/pathsomething/not-an-id:test-thing")))
	assert.False(t, r.Match([]byte("/v1/pathsomething/a4s_aKsdFh723018djsa:other-thing")))
	assert.False(t, r.Match([]byte("/v1/pathsomething/a4s_aKsdFh723018djsa:test-thing-suffix")))
}
