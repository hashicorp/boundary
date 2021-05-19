// +build linux darwin windows

package vault

import "testing"

func init() {
	SkipUnlessDocker = gotDocker
}

func gotDocker(t *testing.T) {}
