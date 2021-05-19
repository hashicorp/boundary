package vault

import "testing"

var SkipUnlessDocker func(t *testing.T) = noDocker

func noDocker(t *testing.T) {
	t.Skip("docker not available")
}
