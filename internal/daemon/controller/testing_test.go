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
	t.Run("start 2 controllers", func(t *testing.T) {
		t.Parallel()
		tc1 := NewTestController(t, nil)
		tc2 := NewTestController(t, nil)
		defer tc1.Shutdown()
		defer tc2.Shutdown()
	})
}
