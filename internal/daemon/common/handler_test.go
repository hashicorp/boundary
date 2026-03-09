// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package common

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/gated"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-sockaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_WrapWithOptionals(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	w := httptest.NewRecorder()
	testWriterWrapper := writerWrapper{w, 0}

	type testNoOptional struct {
		http.ResponseWriter
	}
	type testPusherHijacker struct {
		http.ResponseWriter
		testHijacker
		testPusher
	}
	type testPusherFlusher struct {
		http.ResponseWriter
		testPusher
		testFlusher
	}
	type testFlusherHijacker struct {
		http.ResponseWriter
		testFlusher
		testHijacker
	}

	type testAll struct {
		http.ResponseWriter
		testFlusher
		testHijacker
		testPusher
	}

	tests := []struct {
		name            string
		with            *writerWrapper
		wrap            http.ResponseWriter
		wantFlusher     bool
		wantPusher      bool
		wantHijacker    bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-test-writer",
			wrap:            &testFlusher{},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing writer wrapper",
		},
		{
			name:            "missing-wrapper",
			with:            &testWriterWrapper,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing response writer",
		},
		{
			name: "success-no-optional",
			with: &testWriterWrapper,
			wrap: &testNoOptional{},
		},
		{
			name:        "success-flusher",
			with:        &testWriterWrapper,
			wrap:        &testFlusher{},
			wantFlusher: true,
		},
		{
			name:        "success-flusher-hijacker",
			with:        &testWriterWrapper,
			wrap:        &testFlusherHijacker{},
			wantFlusher: true,
		},
		{
			name:       "success-pusher",
			with:       &testWriterWrapper,
			wrap:       &testPusher{},
			wantPusher: true,
		},
		{
			name:         "success-pusher-hijacker",
			with:         &testWriterWrapper,
			wrap:         &testPusherHijacker{},
			wantHijacker: true,
			wantPusher:   true,
		},
		{
			name:        "success-pusher-flusher",
			with:        &testWriterWrapper,
			wrap:        &testPusherFlusher{},
			wantFlusher: true,
			wantPusher:  true,
		},
		{
			name:         "success-hijacker",
			with:         &testWriterWrapper,
			wrap:         &testHijacker{},
			wantHijacker: true,
		},
		{
			name:         "success-all",
			with:         &testWriterWrapper,
			wrap:         &testAll{},
			wantHijacker: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			wrapped, err := WrapWithOptionals(ctx, tt.with, tt.wrap)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(wrapped)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got %q", tt.wantErrMatch.Code, err.Error())
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(wrapped)
			_, ok := wrapped.(interface{ StatusCode() int })
			assert.Truef(ok, "wanted an response writer that satisfied the StatusCode interface")
			if tt.wantPusher {
				_, ok := wrapped.(http.Pusher)
				assert.Truef(ok, "wanted an response writer that satisfied the http.Pusher interface")
			}
			if tt.wantHijacker {
				_, ok := wrapped.(http.Hijacker)
				assert.Truef(ok, "wanted an response writer that satisfied the http.Hijacker interface")
			}
			if tt.wantFlusher {
				_, ok := wrapped.(http.Flusher)
				assert.Truef(ok, "wanted an response writer that satisfied the http.Flusher interface")
			}
		})
	}
}

func Test_WrapWithEventsHandler(t *testing.T) {
	// This cannot run in parallel because it relies on a pkg var common.privateNets
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	testKms := kms.TestKms(t, conn, wrapper)

	testHander := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		fmt.Fprintln(w, "I'm a little teapot short and stout")
	})

	goodAddr, err := sockaddr.NewIPAddr("127.0.0.1")
	require.NoError(t, err)
	testListenerCfg := cfgListener(goodAddr)
	testListenerCfg.XForwardedForRejectNotPresent = false

	c := event.TestEventerConfig(t, "Test_WrapWithEventsHandler", event.TestWithAuditSink(t), event.TestWithObservationSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	testEventer, err := event.NewEventer(testLogger, testLock, "Test_WrapWithEventsHandler", c.EventerConfig)
	require.NoError(t, err)

	tests := []struct {
		name            string
		h               http.Handler
		e               *event.Eventer
		kms             *kms.Kms
		statusCode      int
		noEventJson     bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing handler",
			e:               testEventer,
			kms:             testKms,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing handler",
		},
		{
			name: "missing eventer",
			h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			}),
			kms:             testKms,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing eventer",
		},
		{
			name:            "missing kms",
			h:               testHander,
			e:               testEventer,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing kms",
		},
		{
			name: "audit-startGatedEvents",
			h:    testHander,
			e: func() *event.Eventer {
				b := &testMockBroker{errorOnSendAudit: true}
				c := event.EventerConfig{AuditEnabled: true}
				e, err := event.NewEventer(testLogger, testLock, "audit-startGatedEvents", c, event.TestWithBroker(t, b))
				require.NoError(t, err)
				return e
			}(),
			kms:         testKms,
			statusCode:  http.StatusInternalServerError,
			noEventJson: true,
		},
		{
			name: "audit-flushGatedEvents",
			h:    testHander,
			e: func() *event.Eventer {
				b := &testMockBroker{errorOnFlush: true}
				c := event.EventerConfig{AuditEnabled: true}
				e, err := event.NewEventer(testLogger, testLock, "audit-flushGatedEvents", c, event.TestWithBroker(t, b))
				require.NoError(t, err)
				return e
			}(),
			kms:         testKms,
			statusCode:  http.StatusTeapot, // this isn't ideal, but the write by the test handler will send an teapot status
			noEventJson: true,
		},
		{
			name:       "success",
			h:          testHander,
			e:          testEventer,
			kms:        testKms,
			statusCode: http.StatusTeapot,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := WrapWithEventsHandler(context.Background(), tt.h, tt.e, tt.kms, testListenerCfg)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got %q", tt.wantErrMatch.Code, err.Error())
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(got)

			req, err := http.NewRequest("GET", "/greeting", nil)
			require.NoError(err)
			rr := httptest.NewRecorder()
			got.ServeHTTP(rr, req)
			assert.Equal(tt.statusCode, rr.Code)

			{ // test that the got observation is what we wanted.
				require.NotNil(c.ObservationEvents)
				defer func() { _ = os.WriteFile(c.ObservationEvents.Name(), nil, 0o666) }()
				b, err := os.ReadFile(c.ObservationEvents.Name())
				assert.NoError(err)

				if tt.noEventJson {
					assert.Lenf(b, 0, "expected no json for internal errors but got %s", string(b))
					return
				}
				got := &cloudevents.Event{}
				err = json.Unmarshal(b, got)
				require.NoErrorf(err, "json: %s", string(b))

				actualJson, err := json.Marshal(got)
				require.NoError(err)

				// set the got values to the wanted values that are either
				// static or calculated in real-time
				info := event.RequestInfo{
					Method: "GET",
					Path:   "/greeting",
					Id:     got.Data.(map[string]any)["request_info"].(map[string]any)["id"].(string),
				}
				hdr := map[string]any{
					"status":     http.StatusTeapot,
					"start":      got.Data.(map[string]any)["start"].(string),
					"stop":       got.Data.(map[string]any)["stop"].(string),
					"latency-ms": got.Data.(map[string]any)["latency-ms"].(float64),
				}
				wantJson := testJson(t, event.ObservationType, &info, event.Op(tt.name), got, hdr, nil)
				assert.JSONEq(string(wantJson), string(actualJson))
			}

			{ // test that the got audit is what we wanted.
				require.NotNil(c.AuditEvents)
				defer func() { _ = os.WriteFile(c.AuditEvents.Name(), nil, 0o666) }()
				b, err := os.ReadFile(c.AuditEvents.Name())
				assert.NoError(err)

				got := &cloudevents.Event{}
				err = json.Unmarshal(b, got)
				require.NoErrorf(err, "json: %s", string(b))

				actualJson, err := json.Marshal(got)
				require.NoError(err)

				// set the got values to the wanted values that are either
				// static or calculated in real-time
				info := event.RequestInfo{
					Method: "GET",
					Path:   "/greeting",
					// Id:     got.Data.(map[string]interface{})["id"].(string),
					Id: got.Data.(map[string]any)["request_info"].(map[string]any)["id"].(string),
				}
				hdr := map[string]any{
					"id":        got.Data.(map[string]any)["id"].(string),
					"timestamp": got.Data.(map[string]any)["timestamp"].(string),
					"response":  got.Data.(map[string]any)["response"].(map[string]any),
				}
				wantJson := testJson(t, event.AuditType, &info, event.Op(tt.name), got, hdr, nil)
				assert.JSONEq(string(wantJson), string(actualJson))

			}
		})
	}
}

func Test_startGatedEvents(t *testing.T) {
	testStartTime := time.Now()
	tests := []struct {
		name             string
		errOnAudit       bool
		errOnObservation bool
		startTime        time.Time
		wantErrMatch     *errors.Template
		wantErrContains  string
	}{
		{
			name:         "audit-failed",
			errOnAudit:   true,
			startTime:    testStartTime,
			wantErrMatch: errors.T(errors.Internal),
		},
		{
			name:             "observation-failed",
			errOnObservation: true,
			wantErrMatch:     errors.T(errors.Internal),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			b := &testMockBroker{
				errorOnSendAudit:       tt.errOnAudit,
				errorOnSendObservation: tt.errOnObservation,
			}
			config := event.EventerConfig{
				AuditEnabled:        true,
				ObservationsEnabled: true,
			}
			testLock := &sync.Mutex{}
			testLogger := hclog.New(&hclog.LoggerOptions{
				Mutex: testLock,
				Name:  "test",
			})
			e, err := event.NewEventer(testLogger, testLock, tt.name, config, event.TestWithBroker(t, b))
			require.NoError(err)
			ctx, err := event.NewEventerContext(context.Background(), e)
			require.NoError(err)
			err = startGatedEvents(ctx, "GET", "/hello", tt.startTime)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got %q", tt.wantErrMatch.Code, err.Error())
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}

func Test_flushGatedEvents(t *testing.T) {
	testStartTime := time.Now()
	tests := []struct {
		name             string
		errOnAudit       bool
		errOnObservation bool
		startTime        time.Time
		wantErrMatch     *errors.Template
		wantErrContains  string
	}{
		{
			name:         "audit-failed",
			errOnAudit:   true,
			startTime:    testStartTime,
			wantErrMatch: errors.T(errors.Internal),
		},
		{
			name:             "observation-failed",
			errOnObservation: true,
			wantErrMatch:     errors.T(errors.Internal),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			b := &testMockBroker{
				errorOnSendAudit:       tt.errOnAudit,
				errorOnSendObservation: tt.errOnObservation,
			}
			config := event.EventerConfig{
				AuditEnabled:        true,
				ObservationsEnabled: true,
			}
			testLock := &sync.Mutex{}
			testLogger := hclog.New(&hclog.LoggerOptions{
				Mutex: testLock,
				Name:  "test",
			})
			e, err := event.NewEventer(testLogger, testLock, tt.name, config, event.TestWithBroker(t, b))
			require.NoError(err)
			ctx, err := event.NewEventerContext(context.Background(), e)
			require.NoError(err)
			err = flushGatedEvents(ctx, "GET", "/hello", 200, tt.startTime)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got %q", tt.wantErrMatch.Code, err.Error())
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}

type testMockBroker struct {
	errorOnSendAudit       bool
	errorOnSendObservation bool
	errorOnFlush           bool
}

func (b *testMockBroker) Send(ctx context.Context, t eventlogger.EventType, payload any) (eventlogger.Status, error) {
	const op = "common.(testMockBroker).Send"
	_, isGateable := payload.(gated.Gateable)
	switch {
	case b.errorOnFlush && isGateable && payload.(gated.Gateable).FlushEvent():
		return eventlogger.Status{}, errors.New(ctx, errors.Internal, op, "unable to flush event")
	case b.errorOnSendAudit && t == eventlogger.EventType(event.AuditType):
		return eventlogger.Status{}, errors.New(ctx, errors.Internal, op, "unable to send audit event")
	case b.errorOnSendObservation && t == eventlogger.EventType(event.ObservationType):
		return eventlogger.Status{}, errors.New(ctx, errors.Internal, op, "unable to send observation event")
	}
	return eventlogger.Status{}, nil
}
func (b *testMockBroker) Reopen(ctx context.Context) error { return nil }
func (b *testMockBroker) RegisterPipeline(def eventlogger.Pipeline, opt ...eventlogger.Option) error {
	return nil
}
func (b *testMockBroker) StopTimeAt(t time.Time) {}

func (b *testMockBroker) RegisterNode(id eventlogger.NodeID, node eventlogger.Node, opt ...eventlogger.Option) error {
	return nil
}

func (b *testMockBroker) RemoveNode(ctx context.Context, id eventlogger.NodeID) error {
	return nil
}

func (b *testMockBroker) RemovePipelineAndNodes(ctx context.Context, t eventlogger.EventType, id eventlogger.PipelineID) (bool, error) {
	return true, nil
}

func (b *testMockBroker) SetSuccessThreshold(t eventlogger.EventType, successThreshold int) error {
	return nil
}

type eventJson struct {
	CreatedAt string         `json:"created_at"`
	EventType string         `json:"event_type"`
	Payload   map[string]any `json:"payload"`
}

func testJson(t *testing.T, eventType event.Type, reqInfo *event.RequestInfo, caller event.Op, got *cloudevents.Event, hdr, details map[string]any) []byte {
	t.Helper()
	const (
		testAuditVersion       = "v0.1"
		testErrorVersion       = "v0.1"
		testObservationVersion = "v0.1"
	)

	require := require.New(t)

	var payload map[string]any
	switch eventType {
	case event.ObservationType:
		payload = map[string]any{
			event.RequestInfoField: reqInfo,
			event.VersionField:     testObservationVersion,
		}
		for k, v := range hdr {
			payload[k] = v
		}
	case event.AuditType:
		payload = map[string]any{
			event.IdField:          got.Data.(map[string]any)[event.IdField].(string),
			event.RequestInfoField: reqInfo,
			event.VersionField:     testAuditVersion,
			event.TypeField:        event.ApiRequest,
		}
		for k, v := range hdr {
			payload[k] = v
		}
	}
	j := cloudevents.Event{
		ID:              got.ID,
		Time:            got.Time,
		Source:          got.Source,
		SpecVersion:     got.SpecVersion,
		Type:            got.Type,
		DataContentType: got.DataContentType,
		Data:            payload,
	}

	if details != nil {
		details[event.OpField] = string(caller)
		d := got.Data.(map[string]any)[event.DetailsField].([]any)[0].(map[string]any)
		j.Data.(map[string]any)[event.DetailsField] = []struct {
			CreatedAt string         `json:"created_at"`
			Type      string         `json:"type"`
			Payload   map[string]any `json:"payload"`
		}{
			{
				CreatedAt: d[event.CreatedAtField].(string),
				Type:      d[event.TypeField].(string),
				Payload:   details,
			},
		}
	}
	b, err := json.Marshal(j)
	require.NoError(err)
	return b
}

type testFlusher struct {
	http.ResponseWriter
}

func (t *testFlusher) Flush() {}

type testPusher struct {
	http.ResponseWriter
}

func (t *testPusher) Push(target string, opts *http.PushOptions) error { return nil }

type testHijacker struct {
	http.ResponseWriter
}

func (t *testHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) { return nil, nil, nil }
