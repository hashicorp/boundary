// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package event

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newCloudEventsFormatterFilter(t *testing.T) {
	t.Parallel()
	testSource, err := url.Parse("https://localhost:9200")
	require.NoError(t, err)
	tests := []struct {
		name            string
		source          *url.URL
		format          cloudevents.Format
		opt             []Option
		wantErr         bool
		wantIsError     error
		wantErrContains string
		wantAllow       []string
		wantDeny        []string
	}{
		{
			name:   "no-opts",
			source: testSource,
			format: cloudevents.FormatJSON,
		},
		{
			name:   "bad-allow-filter",
			source: testSource,
			format: cloudevents.FormatJSON,
			opt: []Option{
				WithAllow("foo=;22", "foo==bar"),
			},
			wantErr:         true,
			wantErrContains: "invalid allow filter 'foo=;22'",
		},
		{
			name:   "bad-deny-filter",
			source: testSource,
			format: cloudevents.FormatJSON,
			opt: []Option{
				WithDeny("foo=;22", "foo==bar"),
			},
			wantErr:         true,
			wantErrContains: "invalid deny filter 'foo=;22'",
		},
		{
			name:   "empty-allow-filter",
			source: testSource,
			format: cloudevents.FormatJSON,
			opt: []Option{
				WithAllow(""),
			},
			wantErr:         true,
			wantErrContains: "missing filter",
		},
		{
			name:   "empty-deny-filter",
			source: testSource,
			format: cloudevents.FormatJSON,
			opt: []Option{
				WithDeny(""),
			},
			wantErr:         true,
			wantErrContains: "missing filter",
		},
		{
			name:   "empty-source",
			format: cloudevents.FormatJSON,
			opt: []Option{
				WithAllow("alice==friend", "bob==friend"),
				WithDeny("eve==acquaintance", "fido!=dog"),
			},
			wantErr:         true,
			wantErrContains: "missing source",
		},
		{
			name:   "bad-format",
			source: testSource,
			format: "invalid-format",
			opt: []Option{
				WithAllow("alice==friend", "bob==friend"),
				WithDeny("eve==acquaintance", "fido!=dog"),
			},
			wantErr:         true,
			wantErrContains: "invalid format",
		},
		{
			name:   "valid-filters",
			source: testSource,
			format: cloudevents.FormatJSON,
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
			got, err := newCloudEventsFormatterFilter(tt.source, tt.format, tt.opt...)
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
			assert.Len(got.allow, len(tt.wantAllow))
			for _, f := range got.allow {
				assert.Contains(tt.wantAllow, f.raw)
			}
			assert.Len(got.deny, len(tt.wantDeny)+1) // +1 since there's always a default deny
			defs, err := defaultCloudEventsDenyFilters()
			require.NoError(err)
			for _, f := range defs {
				tt.wantDeny = append(tt.wantDeny, f.raw)
			}
			for _, f := range got.deny {
				assert.Contains(tt.wantDeny, f.raw)
			}
			assert.Equal([]string{string(AuditType)}, got.SignEventTypes)
		})
	}
}

func TestNode_Process(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	testUrl, err := url.Parse("https://localhost")
	require.NoError(t, err)
	now := time.Now()

	testNode, err := newCloudEventsFormatterFilter(testUrl, cloudevents.FormatJSON, WithSchema(testUrl))
	require.NoError(t, err)

	f, err := newFilter(`data == "match-filter"`)
	require.NoError(t, err)

	tests := []struct {
		name            string
		n               *cloudEventsFormatterFilter
		e               *eventlogger.Event
		format          cloudevents.Format
		predicate       func(ctx context.Context, ce any) (bool, error)
		wantCloudEvent  *cloudevents.Event
		wantText        string
		wantIsError     error
		wantErrContains string
	}{
		{
			name: "simple-JSON",
			n:    testNode,
			e: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   "test-string",
			},
			format: cloudevents.FormatJSON,
			wantCloudEvent: &cloudevents.Event{
				Source:          testUrl.String(),
				DataSchema:      testUrl.String(),
				SpecVersion:     cloudevents.SpecVersion,
				Type:            "test",
				Data:            "test-string",
				DataContentType: "application/cloudevents",
				Time:            now,
			},
		},
		{
			name: "deny-filter-match",
			n:    testNode,
			e: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   "match-filter",
			},
			format:    cloudevents.FormatJSON,
			predicate: newPredicate(nil, []*filter{f}),
		},
		{
			name: "deny-filter-not-matching",
			n:    testNode,
			e: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   "not-matching-filter",
			},
			format:    cloudevents.FormatJSON,
			predicate: newPredicate(nil, []*filter{f}),
			wantCloudEvent: &cloudevents.Event{
				Source:          testUrl.String(),
				DataSchema:      testUrl.String(),
				SpecVersion:     cloudevents.SpecVersion,
				Type:            "test",
				Data:            "not-matching-filter",
				DataContentType: "application/cloudevents",
				Time:            now,
			},
		},
		{
			name: "allow-filter-match",
			n:    testNode,
			e: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   "match-filter",
			},
			format:    cloudevents.FormatJSON,
			predicate: newPredicate([]*filter{f}, nil),
			wantCloudEvent: &cloudevents.Event{
				Source:          testUrl.String(),
				DataSchema:      testUrl.String(),
				SpecVersion:     cloudevents.SpecVersion,
				Type:            "test",
				Data:            "match-filter",
				DataContentType: "application/cloudevents",
				Time:            now,
			},
		},
		{
			name: "allow-filter-not-matching",
			n:    testNode,
			e: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   "not-matching-filter",
			},
			format:    cloudevents.FormatJSON,
			predicate: newPredicate([]*filter{f}, nil),
		},
		{
			name: "no-filters",
			n:    testNode,
			e: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   "test-data",
			},
			format:    cloudevents.FormatJSON,
			predicate: newPredicate(nil, nil),
			wantCloudEvent: &cloudevents.Event{
				Source:          testUrl.String(),
				DataSchema:      testUrl.String(),
				SpecVersion:     cloudevents.SpecVersion,
				Type:            "test",
				Data:            "test-data",
				DataContentType: "application/cloudevents",
				Time:            now,
			},
		},
		{
			name: "simple-Text",
			n:    testNode,
			e: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   "test-string",
			},
			format: cloudevents.FormatText,
			wantCloudEvent: &cloudevents.Event{
				Source:          testUrl.String(),
				DataSchema:      testUrl.String(),
				SpecVersion:     cloudevents.SpecVersion,
				Type:            "test",
				Data:            "test-string",
				DataContentType: "text/plain",
				Time:            now,
			},
			wantText: `{
  "id": "%s",
  "source": "https://localhost",
  "specversion": "1.0",
  "type": "test",
  "data": "test-string",
  "datacontentype": "text/plain",
  "dataschema": "https://localhost",
  "time": %s
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// these subtests cannot be run in parallel since they all depend on
			// a shared testNode which may be modified during the test.
			assert, require := assert.New(t), require.New(t)
			tt.n.Format = tt.format
			tt.n.Predicate = tt.predicate

			gotEvent, err := tt.n.Process(ctx, tt.e)
			if tt.wantIsError != nil {
				require.Error(err)
				assert.Nil(gotEvent)
				assert.ErrorIs(err, tt.wantIsError)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			if tt.wantCloudEvent == nil {
				assert.Nil(gotEvent)
				return
			}
			gotFormatted, ok := gotEvent.Format(string(tt.format))
			require.True(ok)
			var gotCloudEvent cloudevents.Event
			require.NoError(json.Unmarshal(gotFormatted, &gotCloudEvent))
			if tt.wantCloudEvent.ID == "" {
				tt.wantCloudEvent.ID = gotCloudEvent.ID
			}
			var wantJSON []byte
			switch tt.format {
			case cloudevents.FormatJSON:
				wantJSON, err = json.Marshal(tt.wantCloudEvent)
			case cloudevents.FormatText:
				// test the raw JSON
				jsonTime, err := gotCloudEvent.Time.MarshalJSON()
				require.NoError(err)
				wantRawText := []byte(fmt.Sprintf(tt.wantText, gotCloudEvent.ID, jsonTime))
				assert.Equal(string(wantRawText), string(gotFormatted))

				// test the marshaled JSON
				wantJSON, err = json.MarshalIndent(tt.wantCloudEvent, cloudevents.TextIndent, cloudevents.TextIndent)
				require.NoError(err)
			}
			require.NoError(err)
			assert.JSONEq(string(wantJSON), string(gotFormatted))
			t.Log(string(gotFormatted))
		})
	}
}

func Test_cloudEventsFormatter_Rotate(t *testing.T) {
	tests := []struct {
		name            string
		f               *cloudEventsFormatterFilter
		w               wrapping.Wrapper
		wantIsError     error
		wantErrContains string
	}{
		{
			name:            "missing-wrapper",
			f:               &cloudEventsFormatterFilter{FormatterFilter: &cloudevents.FormatterFilter{}},
			wantIsError:     ErrInvalidParameter,
			wantErrContains: "missing wrapper",
		},
		{
			name: "valid",
			f:    &cloudEventsFormatterFilter{FormatterFilter: &cloudevents.FormatterFilter{}},
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
			assert.NotNil(tt.f.Signer)
		})
	}
}
