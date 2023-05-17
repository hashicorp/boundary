package servers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithRotationFrequency", func(t *testing.T) {
		opts := getOpts(WithRotationFrequency(time.Minute))
		testOpts := getDefaultOptions()
		assert.Equal(t, testOpts.withRotationFrequency, defaultRotationFrequency)
		assert.Equal(t, time.Minute, opts.withRotationFrequency)
	})
	t.Run("WithCertificateLifetime", func(t *testing.T) {
		opts := getOpts(WithCertificateLifetime(time.Minute))
		testOpts := getDefaultOptions()
		assert.Equal(t, testOpts.withCertificateLifetime, defaultRotationFrequency)
		assert.Equal(t, time.Minute, opts.withCertificateLifetime)
	})
}
