package common

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_WrapWithOptionals(t *testing.T) {
	t.Parallel()
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
			wrapped, err := WrapWithOptionals(tt.with, tt.wrap)
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
	t.Parallel()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	c := event.TestEventerConfig(t, "Test_WrapWithEventsHandler", event.TestWithAuditSink(t), event.TestWithObservationSink(t))
	testEventer, err := event.NewEventer(hclog.Default(), c.EventerConfig)
	require.NoError(t, err)
	testKms := kms.TestKms(t, conn, wrapper)

	testHander := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		fmt.Fprintln(w, "I'm a little teapot short and stout")
	})
	tests := []struct {
		name            string
		h               http.Handler
		e               *event.Eventer
		logger          hclog.Logger
		kms             *kms.Kms
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing handler",
			e:               testEventer,
			logger:          hclog.Default(),
			kms:             testKms,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing handler",
		},
		{
			name: "missing eventer",
			h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			}),
			logger:          hclog.Default(),
			kms:             testKms,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing eventer",
		},
		{
			name:            "missing logger",
			h:               testHander,
			e:               testEventer,
			kms:             testKms,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing logger",
		},
		{
			name:            "missing kms",
			h:               testHander,
			e:               testEventer,
			logger:          hclog.Default(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing kms",
		},
		{
			name:   "success",
			h:      testHander,
			e:      testEventer,
			logger: hclog.Default(),
			kms:    testKms,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := WrapWithEventsHandler(tt.h, tt.e, tt.logger, tt.kms)
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
			assert.Equal(http.StatusTeapot, rr.Code)

			{ // test that the got observation is what we wanted.
				require.NotNil(c.ObservationEvents)
				defer func() { _ = os.WriteFile(c.ObservationEvents.Name(), nil, 0o666) }()
				b, err := ioutil.ReadFile(c.ObservationEvents.Name())
				assert.NoError(err)

				got := &eventJson{}
				err = json.Unmarshal(b, got)
				require.NoErrorf(err, "json: %s", string(b))

				actualJson, err := json.Marshal(got)
				require.NoError(err)

				// set the got values to the wanted values that are either
				// static or calculated in real-time
				info := event.RequestInfo{
					Method: "GET",
					Path:   "/greeting",
					Id:     got.Payload["id"].(string),
				}
				hdr := map[string]interface{}{
					"status":     http.StatusTeapot,
					"start":      got.Payload["header"].(map[string]interface{})["start"].(string),
					"stop":       got.Payload["header"].(map[string]interface{})["stop"].(string),
					"latency-ms": got.Payload["header"].(map[string]interface{})["latency-ms"].(float64),
				}
				wantJson := testJson(t, event.ObservationType, &info, event.Op(tt.name), got, hdr, nil)
				assert.JSONEq(string(wantJson), string(actualJson))
			}

			{ // test that the got audit is what we wanted.
				require.NotNil(c.AuditEvents)
				defer func() { _ = os.WriteFile(c.AuditEvents.Name(), nil, 0o666) }()
				b, err := ioutil.ReadFile(c.AuditEvents.Name())
				assert.NoError(err)

				got := &eventJson{}
				err = json.Unmarshal(b, got)
				require.NoErrorf(err, "json: %s", string(b))

				actualJson, err := json.Marshal(got)
				require.NoError(err)

				// set the got values to the wanted values that are either
				// static or calculated in real-time
				info := event.RequestInfo{
					Method: "GET",
					Path:   "/greeting",
					Id:     got.Payload["id"].(string),
				}
				hdr := map[string]interface{}{
					"id":              got.Payload["id"].(string),
					"timestamp":       got.Payload["timestamp"].(string),
					"serialized_hmac": got.Payload["serialized_hmac"].(string),
				}
				wantJson := testJson(t, event.AuditType, &info, event.Op(tt.name), got, hdr, nil)
				assert.JSONEq(string(wantJson), string(actualJson))

			}
		})
	}

}

type eventJson struct {
	CreatedAt string                 `json:"created_at"`
	EventType string                 `json:"event_type"`
	Payload   map[string]interface{} `json:"payload"`
}

func testJson(t *testing.T, eventType event.Type, reqInfo *event.RequestInfo, caller event.Op, got *eventJson, hdr, details map[string]interface{}) []byte {
	t.Helper()
	const (
		testAuditVersion       = "v0.1"
		testErrorVersion       = "v0.1"
		testObservationVersion = "v0.1"
	)

	require := require.New(t)

	var payload map[string]interface{}
	switch eventType {
	case event.ObservationType:
		payload = map[string]interface{}{
			event.IdField: got.Payload[event.IdField].(string),
			event.HeaderField: map[string]interface{}{
				event.RequestInfoField: reqInfo,
				event.VersionField:     testObservationVersion,
			},
		}
		h := payload[event.HeaderField].(map[string]interface{})
		for k, v := range hdr {
			h[k] = v
		}
	case event.AuditType:
		payload = map[string]interface{}{
			event.IdField:          got.Payload[event.IdField].(string),
			event.RequestInfoField: reqInfo,
			event.VersionField:     testAuditVersion,
			event.TypeField:        event.ApiRequest,
		}
		for k, v := range hdr {
			payload[k] = v
		}
	}
	j := eventJson{
		CreatedAt: got.CreatedAt,
		EventType: string(eventType),
		Payload:   payload,
	}

	if details != nil {
		details[event.OpField] = string(caller)
		d := got.Payload[event.DetailsField].([]interface{})[0].(map[string]interface{})
		j.Payload[event.DetailsField] = []struct {
			CreatedAt string                 `json:"created_at"`
			Type      string                 `json:"type"`
			Payload   map[string]interface{} `json:"payload"`
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
