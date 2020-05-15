package controller

import (
	"testing"
)

func Test_TestController(t *testing.T) {
	t.Run("startup and shutdown", func(t *testing.T) {
		t.Parallel()
		tc := NewTestController(t, nil)
		defer tc.Shutdown()
	})
}
