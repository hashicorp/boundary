package event

import (
	"context"
	"testing"

	"github.com/hashicorp/eventlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHclogFormatter_Process(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name            string
		formatter       *HclogFormatter
		e               *eventlogger.Event
		wantErrContains string
		want            []string
	}{
		{
			name: "nil event",
			formatter: &HclogFormatter{
				JSONFormat: false,
			},
			wantErrContains: "event is nil",
		},
		{
			name: "invalid-event-type",
			formatter: &HclogFormatter{
				JSONFormat: false,
			},
			e:               &eventlogger.Event{Type: eventlogger.EventType("invalid-type")},
			wantErrContains: "unknown event type invalid-type",
		},
		{
			name: "sys-text",
			formatter: &HclogFormatter{
				JSONFormat: false,
			},
			e: &eventlogger.Event{
				Type: eventlogger.EventType(SystemType),
				Payload: &sysEvent{
					Id:      "1",
					Version: errorVersion,
					Op:      Op("text"),
					Data: map[string]interface{}{
						"msg": "hello",
					},
				},
			},
			want: []string{
				"[INFO]  system event:",
				"Data=map[msg:hello]",
				"Id=1",
				"Version=v0.1",
				"Op=text",
			},
		},
		{
			name: "observation-text",
			formatter: &HclogFormatter{
				JSONFormat: false,
			},
			e: &eventlogger.Event{
				Type: eventlogger.EventType(ObservationType),
				Payload: map[string]interface{}{
					"id":         "1",
					"version":    observationVersion,
					"latency-ms": 10,
				},
			},
			want: []string{
				"[INFO]  observation event:",
				"latency-ms=10",
				"id=1",
				"version=v0.1",
			},
		},
		{
			name: "observation-json",
			formatter: &HclogFormatter{
				JSONFormat: true,
			},
			e: &eventlogger.Event{
				Type: eventlogger.EventType(ObservationType),
				Payload: map[string]interface{}{
					"id":         "1",
					"version":    observationVersion,
					"latency-ms": 10,
				},
			},
			want: []string{
				"{\"@level\":\"info\",\"@message\":\"observation event\"",
				"\"latency-ms\":10",
				"\"id\":\"1\"",
				"\"version\":\"v0.1\"}\n",
			},
		},
		{
			name: "err-text",
			formatter: &HclogFormatter{
				JSONFormat: false,
			},
			e: &eventlogger.Event{
				Type: eventlogger.EventType(ErrorType),
				Payload: &err{
					Id:      "1",
					Version: errorVersion,
					Error:   ErrInvalidParameter.Error(),
					Op:      Op("text"),
				},
			},
			want: []string{
				"[ERROR] error event:",
				"Error=\"invalid parameter\"",
				"Id=1",
				"Version=v0.1",
				"Op=text",
			},
		},
		{
			name: "err-json",
			formatter: &HclogFormatter{
				JSONFormat: true,
			},
			e: &eventlogger.Event{
				Type: eventlogger.EventType(ErrorType),
				Payload: &err{
					Id:      "1",
					Version: errorVersion,
					Error:   ErrInvalidParameter.Error(),
					Op:      Op("text"),
				},
			},
			want: []string{
				"{\"@level\":\"error\",\"@message\":\"error event\"",
				"\"Error\":\"invalid parameter\"",
				"\"Id\":\"1\"",
				"\"Version\":\"v0.1\"",
				"\"Op\":\"text\""},
		},
		{
			name: "err-text-with-optional",
			formatter: &HclogFormatter{
				JSONFormat: false,
			},
			e: &eventlogger.Event{
				Type: eventlogger.EventType(ErrorType),
				Payload: &err{
					Id:      "1",
					Version: errorVersion,
					Error:   ErrInvalidParameter.Error(),
					Op:      Op("text"),
					Info:    map[string]interface{}{"name": "alice"},
				},
			},
			want: []string{
				"[ERROR] error event:",
				"Error=\"invalid parameter\"",
				"Id=1",
				"Version=v0.1",
				"Info=map[name:alice]",
				"Op=text",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			e, err := tt.formatter.Process(ctx, tt.e)
			if tt.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(err)
			assert.NotNil(e)
			var b []byte
			var ok bool
			switch tt.formatter.JSONFormat {
			case true:
				b, ok = e.Format(string(JSONHclogSinkFormat))
			case false:
				b, ok = e.Format(string(TextHclogSinkFormat))
			}
			t.Log(string(b))
			require.True(ok)
			for _, txt := range tt.want {
				assert.Contains(string(b), txt)
			}
		})
	}
}
