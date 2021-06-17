package event

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-hclog"
)

func Test_HclogSink(t *testing.T) {
	t.Run("hclog", func(t *testing.T) {
		ctx := context.Background()
		logger := hclog.New(&hclog.LoggerOptions{
			Name: "test",
			// JSONFormat: true,
		})
		s := HclogSink{
			Logger: logger,
		}
		e := &eventlogger.Event{
			CreatedAt: time.Now(),
			Type:      "test",
			Payload: struct {
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
			},
		}
		_, err := s.Process(ctx, e)
		if err != nil {
			t.Fatalf("unexpected error: %q", err)
		}
	})
}
