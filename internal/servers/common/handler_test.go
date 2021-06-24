package common

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_WrapWithOptionals(t *testing.T) {
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
