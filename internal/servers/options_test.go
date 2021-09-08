package servers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	opts := getOpts()
	assert.Equal(t, options{}, opts)

	opts = getOpts(
		WithLimit(5),
		WithLiveness(time.Hour),
		WithUpdateTags(true),
	)
	exp := options{
		withLimit:      5,
		withLiveness:   time.Hour,
		withUpdateTags: true,
	}
	assert.Equal(t, exp, opts)
}
