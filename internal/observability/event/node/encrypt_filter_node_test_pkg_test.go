package node_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event/node"
	"github.com/hashicorp/eventlogger"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestEncryptFilter_Process(t *testing.T) {
	ctx := context.Background()
	wrapper := node.TestWrapper(t)
	now := time.Now()
	testEncryptingFilter := &node.EncryptFilter{
		Wrapper:  wrapper,
		HmacSalt: []byte("salt"),
		HmacInfo: []byte("info"),
	}

	testString := "test-string"

	tests := []struct {
		name            string
		filter          *node.EncryptFilter
		testEvent       *eventlogger.Event
		setupWantEvent  func(*eventlogger.Event)
		wantEvent       *eventlogger.Event
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:   "simple",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &testPayload{
					notExported:       "not-exported",
					NotTagged:         "not-tagged-data-will-be-redacted",
					SensitiveRedacted: []byte("sensitive-redact-override"),
					UserInfo: &testUserInfo{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe",
					},
					Keys: [][]byte{[]byte("key1"), []byte("key2")},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &testPayload{
					notExported:       "not-exported",
					NotTagged:         node.RedactedData,
					SensitiveRedacted: []byte(node.RedactedData),
					UserInfo: &testUserInfo{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe", // this will be decryped by the setupWantEvent func before comparison
					},
					Keys: [][]byte{[]byte(node.RedactedData), []byte(node.RedactedData)},
				},
			},
			setupWantEvent: func(e *eventlogger.Event) {
				e.Payload.(*testPayload).UserInfo.SensitiveUserName = string(node.TestDecryptValue(t, wrapper, []byte(e.Payload.(*testPayload).UserInfo.SensitiveUserName)))
			},
		},
		{
			name:   "nil-byte-fields",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &testPayload{
					NotTagged:         "not-tagged-data-will-be-redacted",
					SensitiveRedacted: nil,
					UserInfo: &testUserInfo{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe",
					},
					Keys: nil,
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &testPayload{
					NotTagged:         node.RedactedData,
					SensitiveRedacted: nil,
					UserInfo: &testUserInfo{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe", // this will be decryped by the setupWantEvent func before comparison
					},
					Keys: nil,
				},
			},
			setupWantEvent: func(e *eventlogger.Event) {
				e.Payload.(*testPayload).UserInfo.SensitiveUserName = string(node.TestDecryptValue(t, wrapper, []byte(e.Payload.(*testPayload).UserInfo.SensitiveUserName)))
			},
		},
		{
			name:   "taggable",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &node.TestTaggedMap{
					"foo": "bar",
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &node.TestTaggedMap{
					"foo": "<REDACTED>",
				},
			},
		},
		{
			name:   "nil-payload",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   nil,
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   nil,
			},
		},
		{
			name:   "string-ptr-payload",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   &testString,
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   func() interface{} { s := node.RedactedData; return &s }(),
			},
		},
		{
			name:   "string-payload",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   testString,
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "unable to redact string payload (not setable)",
		},
		{
			name:            "missing-event",
			filter:          testEncryptingFilter,
			testEvent:       nil,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing event",
		},
		{
			name:   "missing-wrapper",
			filter: &node.EncryptFilter{},
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   nil,
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing wrapper",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := tt.filter.Process(ctx, tt.testEvent)

			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err %q and got %q", tt.wantErrMatch, err.Error())
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			if tt.setupWantEvent != nil {
				tt.setupWantEvent(got)
			}
			assert.Equal(tt.wantEvent, got)
		})
	}
}

func testEncryptValue(t *testing.T, w wrapping.Wrapper, value []byte) string {
	t.Helper()
	require := require.New(t)
	blobInfo, err := w.Encrypt(context.Background(), value, nil)
	require.NoError(err)
	marshaledBlob, err := proto.Marshal(blobInfo)
	require.NoError(err)
	return "encrypted:" + base64.RawURLEncoding.EncodeToString(marshaledBlob)
}

type testUserInfo struct {
	PublicId          string `classified:"public"`
	SensitiveUserName string `classified:"sensitive"`
	LoginTimestamp    time.Time
}

type testPayload struct {
	notExported       string
	NotTagged         string
	SensitiveRedacted []byte `classified:"sensitive,redact"`
	UserInfo          *testUserInfo
	Keys              [][]byte `classified:"secret"`
}

func TestEncryptFilter_Type(t *testing.T) {
	t.Parallel()
	ef := &node.EncryptFilter{}
	assert.Equalf(t, eventlogger.NodeTypeFilter, ef.Type(), "Type() should always return %s", eventlogger.NodeTypeFilter)
}

func TestEncryptFilter_Reopen(t *testing.T) {
	t.Parallel()
	ef := &node.EncryptFilter{}
	require.NoErrorf(t, ef.Reopen(), "Reopen is a no op and should never return an error")
}

func TestEncryptFilter_Rotate(t *testing.T) {
	t.Parallel()

	initialWrapper := node.TestWrapper(t)

	rotatedWrapper := node.TestWrapper(t)

	tests := []struct {
		name         string
		node         *node.EncryptFilter
		opt          []node.Option
		wantWrapper  wrapping.Wrapper
		wantSalt     []byte
		wantwithInfo []byte
	}{
		{
			name: "wrapper-only",
			node: &node.EncryptFilter{
				Wrapper:  initialWrapper,
				HmacSalt: []byte("initial-salt"),
				HmacInfo: []byte("initial-info"),
			},
			opt:          []node.Option{node.WithWrapper(rotatedWrapper)},
			wantWrapper:  rotatedWrapper,
			wantSalt:     []byte("initial-salt"),
			wantwithInfo: []byte("initial-info"),
		},
		{
			name: "salt-only",
			node: &node.EncryptFilter{
				Wrapper:  initialWrapper,
				HmacSalt: []byte("initial-salt"),
				HmacInfo: []byte("initial-info"),
			},
			opt:          []node.Option{node.WithSalt([]byte("rotated-salt"))},
			wantWrapper:  initialWrapper,
			wantSalt:     []byte("rotated-salt"),
			wantwithInfo: []byte("initial-info"),
		},
		{
			name: "info-only",
			node: &node.EncryptFilter{
				Wrapper:  initialWrapper,
				HmacSalt: []byte("initial-salt"),
				HmacInfo: []byte("initial-info"),
			},
			opt:          []node.Option{node.WithInfo([]byte("rotated-info"))},
			wantWrapper:  initialWrapper,
			wantSalt:     []byte("initial-salt"),
			wantwithInfo: []byte("rotated-info"),
		},
		{
			name: "rotate-everything",
			node: &node.EncryptFilter{
				Wrapper:  initialWrapper,
				HmacSalt: []byte("initial-salt"),
				HmacInfo: []byte("initial-info"),
			},
			opt: []node.Option{
				node.WithWrapper(rotatedWrapper),
				node.WithSalt([]byte("rotated-salt")),
				node.WithInfo([]byte("rotated-info")),
			},
			wantWrapper:  rotatedWrapper,
			wantSalt:     []byte("rotated-salt"),
			wantwithInfo: []byte("rotated-info"),
		},
	}
	for _, tt := range tests {
		assert := assert.New(t)
		tt.node.Rotate(tt.opt...)
		assert.Equal(tt.wantWrapper, tt.node.Wrapper)
		assert.Equal(tt.wantSalt, tt.node.HmacSalt)
		assert.Equal(tt.wantwithInfo, tt.node.HmacInfo)
	}

}
