// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogHandler(t *testing.T) {
	ctx := context.Background()
	lh, err := newLogHandlerFunc(ctx)
	require.NoError(t, err)
	expectedErroringMux := http.NewServeMux()
	expectedErroringMux.HandleFunc("/v1/log", lh)

	t.Run("get", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/log", nil)
		expectedErroringMux.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Result().StatusCode)
	})

	t.Run("delete", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/v1/log", nil)
		expectedErroringMux.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Result().StatusCode)
	})

	t.Run("success", func(t *testing.T) {
		c := event.TestEventerConfig(t, "TestLogHandler_success")
		testLock := &sync.Mutex{}
		testLogger := hclog.New(&hclog.LoggerOptions{
			Mutex:      testLock,
			Name:       "test",
			JSONFormat: true,
		})
		require.NoError(t, event.InitSysEventer(testLogger, testLock, "TestLogHandler_success", event.WithEventerConfig(&c.EventerConfig)))
		ctx, err := event.NewEventerContext(context.Background(), event.SysEventer())
		require.NoError(t, err)

		lh, err := newLogHandlerFunc(ctx)
		require.NoError(t, err)
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/log", lh)

		rec := httptest.NewRecorder()
		b, err := json.Marshal(&LogRequest{
			Message: "test message",
			Op:      "test op",
		})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/v1/log", bytes.NewReader(b))
		mux.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Result().StatusCode)

		sinkFileName := c.AllEvents.Name()
		defer func() { _ = os.WriteFile(sinkFileName, nil, 0o666) }()
		b, err = os.ReadFile(sinkFileName)
		require.NoError(t, err)
		gotEvent := &cloudevents.Event{}
		err = json.Unmarshal(b, gotEvent)
		require.NoError(t, err)

		gotData := gotEvent.Data.(map[string]any)["data"].(map[string]any)
		assert.Equal(t, "test message", gotData["msg"])
		assert.Equal(t, "test op", gotData["requester_op"])
	})

	t.Run("success failed unmarshaling", func(t *testing.T) {
		c := event.TestEventerConfig(t, "TestLogHandler_success")
		testLock := &sync.Mutex{}
		testLogger := hclog.New(&hclog.LoggerOptions{
			Mutex:      testLock,
			Name:       "test",
			JSONFormat: true,
		})
		require.NoError(t, event.InitSysEventer(testLogger, testLock, "TestLogHandler_success", event.WithEventerConfig(&c.EventerConfig)))
		ctx, err := event.NewEventerContext(context.Background(), event.SysEventer())
		require.NoError(t, err)

		lh, err := newLogHandlerFunc(ctx)
		require.NoError(t, err)
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/log", lh)

		rec := httptest.NewRecorder()
		b := []byte("not json")
		req := httptest.NewRequest(http.MethodPost, "/v1/log", bytes.NewReader(b))
		mux.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Result().StatusCode)

		sinkFileName := c.AllEvents.Name()
		defer func() { _ = os.WriteFile(sinkFileName, nil, 0o666) }()
		b, err = os.ReadFile(sinkFileName)
		require.NoError(t, err)
		gotEvent := &cloudevents.Event{}
		err = json.Unmarshal(b, gotEvent)
		require.NoError(t, err)

		gotData := gotEvent.Data.(map[string]any)
		assert.NotEmpty(t, gotData["error"])
		assert.Equal(t, "not json", gotData["info"].(map[string]any)["body"])
	})
}
