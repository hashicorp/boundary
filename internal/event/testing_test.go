// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			_, _ = io.Copy(&buf, r)
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

func Test_CloudEventsFromFile_CloudEventFromBuf(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tmpFile, err := os.CreateTemp("./", "tmp-event")
	require.NoError(err)
	t.Cleanup(func() {
		_ = os.Remove(tmpFile.Name())
	})

	e := &cloudevents.Event{
		ID:     "id",
		Source: "test",
		Data: map[string]any{
			"test": "data",
		},
	}
	j, err := json.Marshal(e)
	require.NoError(err)
	require.NoError(os.WriteFile(tmpFile.Name(), j, 0o666))
	got := event.CloudEventFromFile(t, tmpFile.Name())
	assert.Equal(e, got)

	got = event.CloudEventFromBuf(t, j)
	assert.Equal(e, got)
}
