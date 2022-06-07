package controller

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
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
	t.Run("controller-without-eventing", func(t *testing.T) {
		const op = "Test_TestWithoutEventing"
		assert := assert.New(t)

		// this isn't the best solution for capturing stdout but it works for now...
		captureFn := func(fn func()) string {
			old := os.Stdout
			defer func() {
				os.Stderr = old
			}()

			r, w, _ := os.Pipe()
			os.Stderr = w

			{
				fn()
			}

			outC := make(chan string)
			// copy the output in a separate goroutine so writing to stderr can't block indefinitely
			go func() {
				var buf bytes.Buffer
				io.Copy(&buf, r)
				outC <- buf.String()
			}()

			// back to normal state
			w.Close()
			return <-outC
		}

		assert.Empty(captureFn(func() {
			tc := NewTestController(t, &TestControllerOpts{DisableEventing: true})
			defer tc.Shutdown()
		}))
		assert.NotEmpty(captureFn(func() {
			tc := NewTestController(t, nil)
			defer tc.Shutdown()
		}))
	})
}
