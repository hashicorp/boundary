// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/eventlogger"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHclogFormatter_Process(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	f, e := newFilter(`op == "match-filter"`)
	require.NoError(t, e)

	testPredicate := newPredicate([]*filter{f}, nil)

	tests := []struct {
		name            string
		formatter       *hclogFormatterFilter
		e               *eventlogger.Event
		wantErrContains string
		want            []string
	}{
		{
			name: "nil event",
			formatter: &hclogFormatterFilter{
				jsonFormat: false,
			},
			wantErrContains: "event is nil",
		},
		{
			name: "invalid-event-type",
			formatter: &hclogFormatterFilter{
				jsonFormat: false,
			},
			e:               &eventlogger.Event{Type: eventlogger.EventType("invalid-type")},
			wantErrContains: "unknown event type invalid-type",
		},
		{
			name: "sys-text",
			formatter: &hclogFormatterFilter{
				jsonFormat: false,
			},
			e: &eventlogger.Event{
				Type: eventlogger.EventType(SystemType),
				Payload: &sysEvent{
					Id:      "1",
					Version: errorVersion,
					Op:      Op("text"),
					Data: map[string]any{
						"msg": "hello",
					},
				},
			},
			want: []string{
				"[INFO]  system event:",
				"data:msg=hello",
				"version=v0.1",
				"op=text",
			},
		},
		{
			name: "observation-text",
			formatter: &hclogFormatterFilter{
				jsonFormat: false,
			},
			e: &eventlogger.Event{
				Type: eventlogger.EventType(ObservationType),
				Payload: map[string]any{
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
			formatter: &hclogFormatterFilter{
				jsonFormat: true,
			},
			e: &eventlogger.Event{
				Type: eventlogger.EventType(ObservationType),
				Payload: map[string]any{
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
			formatter: &hclogFormatterFilter{
				jsonFormat: false,
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
				"error=\"invalid parameter\"",
				"id=1",
				"version=v0.1",
				"op=text",
			},
		},
		{
			name: "err-json",
			formatter: &hclogFormatterFilter{
				jsonFormat: true,
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
				"\"error\":\"invalid parameter\"",
				"\"id\":\"1\"",
				"\"version\":\"v0.1\"",
				"\"op\":\"text\"",
			},
		},
		{
			name: "err-text-with-optional",
			formatter: &hclogFormatterFilter{
				jsonFormat: false,
			},
			e: &eventlogger.Event{
				Type: eventlogger.EventType(ErrorType),
				Payload: &err{
					Id:      "1",
					Version: errorVersion,
					Error:   ErrInvalidParameter.Error(),
					Op:      Op("text"),
					Info:    map[string]any{"name": "alice"},
				},
			},
			want: []string{
				"[ERROR] error event:",
				"error=\"invalid parameter\"",
				"id=1",
				"version=v0.1",
				"info:name=alice",
				"op=text",
			},
		},
		{
			name: "filter-match",
			formatter: &hclogFormatterFilter{
				jsonFormat: false,
				predicate:  testPredicate,
			},
			e: &eventlogger.Event{
				Type: eventlogger.EventType(SystemType),
				Payload: &sysEvent{
					Id:      "1",
					Version: errorVersion,
					Op:      Op("match-filter"),
					Data: map[string]any{
						"msg": "hello",
					},
				},
			},
			want: []string{
				"[INFO]  system event:",
				"data:msg=hello",
				"version=v0.1",
				"op=match-filter",
			},
		},
		{
			name: "filter-no-match",
			formatter: &hclogFormatterFilter{
				jsonFormat: false,
				predicate:  testPredicate,
			},
			e: &eventlogger.Event{
				Type: eventlogger.EventType(SystemType),
				Payload: &sysEvent{
					Id:      "1",
					Version: errorVersion,
					Op:      Op("doesn't match"),
					Data: map[string]any{
						"msg": "hello",
					},
				},
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
			if len(tt.want) == 0 {
				assert.Nil(e)
				return
			}
			assert.NotNil(e)
			var b []byte
			var ok bool
			switch tt.formatter.jsonFormat {
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
	t.Run("with-signing", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		wrapper := testWrapper(t)
		f, err := newHclogFormatterFilter(true) // produce json formatted events
		require.NoError(err)
		require.NoError(f.Rotate(wrapper))
		require.NotNil(f.signer)

		e := &eventlogger.Event{
			Type: eventlogger.EventType(AuditType),
			Payload: &audit{
				Id:      "1",
				Version: auditVersion,
				Auth:    &Auth{UserName: "alice"},
			},
		}

		gotEvent, err := f.Process(ctx, e)
		require.NoError(err)
		b, ok := gotEvent.Format(string(JSONHclogSinkFormat))
		require.True(ok)
		var rep map[string]any
		require.NoError(json.Unmarshal(b, &rep))
		assert.NotEmpty(rep["serialized"])
		assert.NotEmpty(rep["serialized_hmac"])
	})
}

func Test_hclogFormatterFilter_Name(t *testing.T) {
	t.Parallel()
	t.Run("simple", func(t *testing.T) {
		ff := &hclogFormatterFilter{}
		assert.Equal(t, hclogNodeName, ff.Name())
	})
}

func Test_hclogFormatterFilter_Reopen(t *testing.T) {
	t.Parallel()
	t.Run("simple", func(t *testing.T) {
		ff := &hclogFormatterFilter{}
		assert.Equal(t, nil, ff.Reopen())
	})
}

func Test_hclogFormatterFilter_Type(t *testing.T) {
	t.Parallel()
	t.Run("simple", func(t *testing.T) {
		ff := &hclogFormatterFilter{}
		assert.Equal(t, eventlogger.NodeTypeFormatterFilter, ff.Type())
	})
}

func Test_newHclogFormatterFilter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		jsonFormat      bool
		opt             []Option
		wantErr         bool
		wantIsError     error
		wantErrContains string
		wantAllow       []string
		wantDeny        []string
	}{
		{
			name: "no-opts",
		},
		{
			name:       "bad-allow-filter",
			jsonFormat: true,
			opt: []Option{
				WithAllow("foo=;22", "foo==bar"),
			},
			wantErr:         true,
			wantErrContains: "invalid allow filter 'foo=;22'",
		},
		{
			name:       "bad-deny-filter",
			jsonFormat: true,
			opt: []Option{
				WithDeny("foo=;22", "foo==bar"),
			},
			wantErr:         true,
			wantErrContains: "invalid deny filter 'foo=;22'",
		},
		{
			name:       "empty-allow-filter",
			jsonFormat: true,
			opt: []Option{
				WithAllow(""),
			},
			wantErr:         true,
			wantErrContains: "missing filter",
		},
		{
			name:       "empty-deny-filter",
			jsonFormat: true,
			opt: []Option{
				WithDeny(""),
			},
			wantErr:         true,
			wantErrContains: "missing filter",
		},
		{
			name:       "valid-filters",
			jsonFormat: true,
			opt: []Option{
				WithAllow("alice==friend", "bob==friend"),
				WithDeny("eve==acquaintance", "fido!=dog"),
			},
			wantAllow: []string{"alice==friend", "bob==friend"},
			wantDeny:  []string{"eve==acquaintance", "fido!=dog"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newHclogFormatterFilter(tt.jsonFormat, tt.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				if tt.wantIsError != nil {
					assert.ErrorIs(err, tt.wantIsError)
				}
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(got)

			assert.Equal(tt.jsonFormat, got.jsonFormat)

			assert.Len(got.allow, len(tt.wantAllow))
			for _, f := range got.allow {
				assert.Contains(tt.wantAllow, f.raw)
			}
			assert.Len(got.deny, len(tt.wantDeny)+4) // +4 since there's always a default deny
			defs, err := defaultHclogEventsDenyFilters()
			require.NoError(err)
			for _, f := range defs {
				tt.wantDeny = append(tt.wantDeny, f.raw)
			}
			for _, f := range got.deny {
				assert.Contains(tt.wantDeny, f.raw)
			}
		})
	}
}

func Test_hclogFormatterFilter_Rotate(t *testing.T) {
	tests := []struct {
		name            string
		f               *hclogFormatterFilter
		w               wrapping.Wrapper
		wantIsError     error
		wantErrContains string
	}{
		{
			name:            "missing-wrapper",
			f:               &hclogFormatterFilter{},
			wantIsError:     ErrInvalidParameter,
			wantErrContains: "missing wrapper",
		},
		{
			name: "valid",
			f:    &hclogFormatterFilter{},
			w:    testWrapper(t),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.f.Rotate(tt.w)
			if tt.wantIsError != nil {
				require.Error(err)
				assert.ErrorIs(err, tt.wantIsError)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			assert.NotNil(tt.f.signer)
		})
	}
}
