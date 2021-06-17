package event

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_HclogSink(t *testing.T) {
	ctx := context.Background()
	var testBuffer strings.Builder
	testPayload := struct {
		Name   string
		Pet    string
		Map    map[string]interface{}
		Struct struct{ name string }
	}{
		Name: "alice",
		Pet:  "fido",
		Map: map[string]interface{}{
			"now":   time.Now(),
			"total": 22,
		},
		Struct: struct{ name string }{
			name: "testing name",
		},
	}
	tests := []struct {
		name    string
		logger  hclog.Logger
		payload interface{}
	}{
		{
			name: "default-fmt",
			logger: hclog.New(&hclog.LoggerOptions{
				Name:   "test",
				Output: &testBuffer,
			}),
			payload: testPayload,
		},
		{
			name: "json-fmt",
			logger: hclog.New(&hclog.LoggerOptions{
				Name:       "json",
				JSONFormat: true,
				Output:     &testBuffer,
			}),
			payload: testPayload,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testBuffer.Reset()
			s := HclogSink{
				Logger: tt.logger,
			}
			e := &eventlogger.Event{
				CreatedAt: time.Now(),
				Type:      "test",
				Payload:   tt.payload,
			}
			_, err := s.Process(ctx, e)
			require.NoError(err)
			assert.Contains(testBuffer.String(), "alice")
			t.Log(testBuffer.String())

		})
	}
}
