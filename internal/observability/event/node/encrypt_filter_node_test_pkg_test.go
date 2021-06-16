package node_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event/node"
	"github.com/hashicorp/eventlogger"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testPayloadStruct struct {
	PublicId          string `classified:"public"`
	SensitiveUserName string `classified:"sensitive"`
	LoginTimestamp    time.Time
	TaggedMap         node.TestTaggedMap
}

type testPayload struct {
	notExported       string
	NotTagged         string
	SensitiveRedacted []byte `classified:"sensitive,redact"`
	StructPtr         *testPayloadStruct
	StructValue       testPayloadStruct
	StructPtrSlice    []*testPayloadStruct
	StructValueSlice  []testPayloadStruct
	Keys              [][]byte `classified:"secret"`
}

type testWrapperPayload struct {
	wrapper wrapping.Wrapper
	salt    []byte
	info    []byte
}

func (t *testWrapperPayload) Wrapper() wrapping.Wrapper { return t.wrapper }
func (t *testWrapperPayload) HmacSalt() []byte          { return t.salt }
func (t *testWrapperPayload) HmacInfo() []byte          { return t.info }

type testEventWrapperPayload struct {
	eventId     string
	salt        []byte
	info        []byte
	StructValue testPayloadStruct
}

func (t *testEventWrapperPayload) EventId() string  { return t.eventId }
func (t *testEventWrapperPayload) HmacSalt() []byte { return t.salt }
func (t *testEventWrapperPayload) HmacInfo() []byte { return t.info }

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
					StructPtr: &testPayloadStruct{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe",
					},
					StructValue: testPayloadStruct{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe",
					},
					StructPtrSlice: []*testPayloadStruct{
						{
							PublicId:          "id-12",
							SensitiveUserName: "Alice Eve Doe",
						},
					},
					StructValueSlice: []testPayloadStruct{
						{
							PublicId:          "id-12",
							SensitiveUserName: "Alice Eve Doe",
						},
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
					StructPtr: &testPayloadStruct{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe", // this will be decryped by the setupWantEvent func before comparison
					},
					StructValue: testPayloadStruct{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe", // this will be decryped by the setupWantEvent func before comparison
					},
					StructPtrSlice: []*testPayloadStruct{
						{
							PublicId:          "id-12",
							SensitiveUserName: "Alice Eve Doe",
						},
					},
					StructValueSlice: []testPayloadStruct{
						{
							PublicId:          "id-12",
							SensitiveUserName: "Alice Eve Doe",
						},
					},
					Keys: [][]byte{[]byte(node.RedactedData), []byte(node.RedactedData)},
				},
			},
			setupWantEvent: func(e *eventlogger.Event) {
				e.Payload.(*testPayload).StructPtr.SensitiveUserName = string(node.TestDecryptValue(t, wrapper, []byte(e.Payload.(*testPayload).StructPtr.SensitiveUserName)))
				e.Payload.(*testPayload).StructValue.SensitiveUserName = string(node.TestDecryptValue(t, wrapper, []byte(e.Payload.(*testPayload).StructValue.SensitiveUserName)))
				e.Payload.(*testPayload).StructPtrSlice[0].SensitiveUserName = string(node.TestDecryptValue(t, wrapper, []byte(e.Payload.(*testPayload).StructPtrSlice[0].SensitiveUserName)))
				e.Payload.(*testPayload).StructValueSlice[0].SensitiveUserName = string(node.TestDecryptValue(t, wrapper, []byte(e.Payload.(*testPayload).StructValueSlice[0].SensitiveUserName)))
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
					StructPtr: &testPayloadStruct{
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
					StructPtr: &testPayloadStruct{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe", // this will be decryped by the setupWantEvent func before comparison
					},
					Keys: nil,
				},
			},
			setupWantEvent: func(e *eventlogger.Event) {
				e.Payload.(*testPayload).StructPtr.SensitiveUserName = string(node.TestDecryptValue(t, wrapper, []byte(e.Payload.(*testPayload).StructPtr.SensitiveUserName)))
				e.Payload.(*testPayload).StructValue.SensitiveUserName = string(node.TestDecryptValue(t, wrapper, []byte(e.Payload.(*testPayload).StructValue.SensitiveUserName)))
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
			name:   "taggable-value",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: node.TestTaggedMap{
					"foo": "bar",
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: node.TestTaggedMap{
					"foo": "<REDACTED>",
				},
			},
		},
		{
			name:   "struct-with-taggable",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &testPayloadStruct{
					PublicId:          "id-12",
					SensitiveUserName: "Alice Eve Doe",
					TaggedMap: node.TestTaggedMap{
						"foo": "bar",
					},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &testPayloadStruct{
					PublicId:          "id-12",
					SensitiveUserName: "Alice Eve Doe",
					TaggedMap: node.TestTaggedMap{
						"foo": "<REDACTED>",
					},
				},
			},
			setupWantEvent: func(e *eventlogger.Event) {
				e.Payload.(*testPayloadStruct).SensitiveUserName = string(node.TestDecryptValue(t, wrapper, []byte(e.Payload.(*testPayloadStruct).SensitiveUserName)))
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
			name:   "slice-struct-payload",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: []testPayloadStruct{
					{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe",
					},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: []testPayloadStruct{
					{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe",
					},
				},
			},
			setupWantEvent: func(e *eventlogger.Event) {
				e.Payload.([]testPayloadStruct)[0].SensitiveUserName = string(node.TestDecryptValue(t, wrapper, []byte(e.Payload.([]testPayloadStruct)[0].SensitiveUserName)))
			},
		},
		{
			name:   "slice-struct-ptr-payload",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: []*testPayloadStruct{
					{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe",
					},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: []*testPayloadStruct{
					{
						PublicId:          "id-12",
						SensitiveUserName: "Alice Eve Doe",
					},
				},
			},
			setupWantEvent: func(e *eventlogger.Event) {
				e.Payload.([]*testPayloadStruct)[0].SensitiveUserName = string(node.TestDecryptValue(t, wrapper, []byte(e.Payload.([]*testPayloadStruct)[0].SensitiveUserName)))
			},
		},
		{
			name:   "ptr-slice-string-payload",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   &[]string{"test"},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   &[]string{node.RedactedData},
			},
		},
		{
			name:   "slice-string-payload",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   []string{"test"},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   []string{node.RedactedData},
			},
		},
		{
			name:   "ptr-slice-string-ptr-payload",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: func() interface{} {
					s := "test"
					return &[]*string{&s}
				}(),
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: func() interface{} {
					s := node.RedactedData
					return &[]*string{&s}
				}(),
			},
		},
		{
			name:   "slice-string-ptr-payload",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: func() interface{} {
					s := "test"
					return []*string{&s}
				}(),
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: func() interface{} {
					s := node.RedactedData
					return []*string{&s}
				}(),
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
	t.Run("rotate-wrapper-payload", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		wrapper := node.TestWrapper(t)
		ef := &node.EncryptFilter{
			Wrapper:  wrapper,
			HmacSalt: []byte("salt"),
			HmacInfo: []byte("info"),
		}
		rotatedWrapper := node.TestWrapper(t)
		e := &eventlogger.Event{
			Payload: &testWrapperPayload{
				wrapper: rotatedWrapper,
				info:    []byte("rotated-info"),
				salt:    []byte("rotated-salt"),
			},
		}
		got, err := ef.Process(context.Background(), e)
		require.NoError(err)
		assert.Nil(got)
		assert.Equal(rotatedWrapper, ef.Wrapper)
		assert.Equal([]byte("rotated-info"), ef.HmacInfo)
		assert.Equal([]byte("rotated-salt"), ef.HmacSalt)
	})
	t.Run("event-wrapper-info-payload-encrypt", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		wrapper := node.TestWrapper(t)
		ef := &node.EncryptFilter{
			Wrapper:  wrapper,
			HmacSalt: []byte("salt"),
			HmacInfo: []byte("info"),
		}
		now := time.Now()
		e := &eventlogger.Event{
			Type:      "test",
			CreatedAt: now,
			Payload: &testEventWrapperPayload{
				eventId: "event-id",
				info:    []byte("event-info"),
				salt:    []byte("event-salt"),
				StructValue: testPayloadStruct{
					PublicId:          "id-12",
					SensitiveUserName: "Alice Eve Doe",
				},
			},
		}
		want := &eventlogger.Event{
			Type:      "test",
			CreatedAt: now,
			Payload: &testEventWrapperPayload{
				eventId: "event-id",
				info:    []byte("event-info"),
				salt:    []byte("event-salt"),
				StructValue: testPayloadStruct{
					PublicId:          "id-12",
					SensitiveUserName: "Alice Eve Doe",
				},
			},
		}
		got, err := ef.Process(context.Background(), e)
		require.NoError(err)
		assert.NotNil(got)
		assert.Equal(wrapper, ef.Wrapper)
		assert.Equal([]byte("info"), ef.HmacInfo)
		assert.Equal([]byte("salt"), ef.HmacSalt)
		eventWrapper, err := node.NewEventWrapper(wrapper, "event-id")
		require.NoError(err)

		e.Payload.(*testEventWrapperPayload).StructValue.SensitiveUserName = string(node.TestDecryptValue(t, eventWrapper, []byte(e.Payload.(*testEventWrapperPayload).StructValue.SensitiveUserName)))
		assert.Equal(want, got)
	})
	t.Run("event-wrapper-info-payload-hmac", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		now := time.Now()
		wrapper := node.TestWrapper(t)
		ef := &node.EncryptFilter{
			Wrapper:  wrapper,
			HmacSalt: []byte("salt"),
			HmacInfo: []byte("info"),
		}
		e := &eventlogger.Event{
			Type:      "test",
			CreatedAt: now,
			Payload: &testEventWrapperPayload{
				eventId: "event-id",
				info:    []byte("event-info"),
				salt:    []byte("event-salt"),
				StructValue: testPayloadStruct{
					PublicId:          "id-12",
					SensitiveUserName: "Alice Eve Doe",
				},
			},
		}
		wantHmac := &eventlogger.Event{
			Type:      "test",
			CreatedAt: now,
			Payload: &testEventWrapperPayload{
				eventId: "event-id",
				info:    []byte("event-info"),
				salt:    []byte("event-salt"),
				StructValue: testPayloadStruct{
					PublicId:          "id-12",
					SensitiveUserName: "Alice Eve Doe",
				},
			},
		}
		ef.FilterOperationOverrides = map[node.DataClassification]node.FilterOperation{
			node.SensitiveClassification: node.HmacSha256Operation,
		}

		got, err := ef.Process(context.Background(), e)
		require.NoError(err)
		assert.NotNil(got)
		testWrapper, err := node.NewEventWrapper(wrapper, "event-id")
		require.NoError(err)
		wantHmac.Payload.(*testEventWrapperPayload).StructValue.SensitiveUserName = node.TestHmacSha256(t, []byte("Alice Eve Doe"), testWrapper, []byte("event-salt"), []byte("event-info"))
		assert.Equal(wantHmac, got)
	})
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
