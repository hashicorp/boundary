package metrics

import (
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/internal/gen/testing/protooptions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestServicePathsAndMethods(t *testing.T) {
	paths := make(map[string][]string)
	require.NoError(t, gatherServicePathsAndMethods(protooptions.File_testing_options_v1_service_proto, paths))
	assert.Equal(t, map[string][]string{
		"/v1/test/{id}": {http.MethodGet},
		"/v2/test":      {http.MethodGet},
	}, paths)
}
