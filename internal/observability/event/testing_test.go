package event_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/stretchr/testify/assert"
)

func Test_TestWithoutEventing(t *testing.T) {
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

	assert.NotEmpty(captureFn(func() {
		fmt.Fprintln(os.Stderr, "not-empty")
	}))

	assert.Empty(captureFn(func() {
		testCtx := context.Background()
		event.TestWithoutEventing(t)
		event.WriteSysEvent(testCtx, op, "test-event")
	}))
}
