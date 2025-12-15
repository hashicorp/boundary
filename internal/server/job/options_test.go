// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package servers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithRotationFrequency", func(t *testing.T) {
		testOpts := getDefaultOptions()
		assert.Equal(t, testOpts.withRotationFrequency, defaultRotationFrequency)
		opts := getOpts(WithRotationFrequency(time.Minute))
		assert.Equal(t, time.Minute, opts.withRotationFrequency)
	})
	t.Run("WithCertificateLifetime", func(t *testing.T) {
		testOpts := getDefaultOptions()
		assert.Equal(t, testOpts.withCertificateLifetime, time.Duration(0))
		opts := getOpts(WithCertificateLifetime(time.Minute))
		assert.Equal(t, time.Minute, opts.withCertificateLifetime)
	})
}
