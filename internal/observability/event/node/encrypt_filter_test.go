package node_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

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

	tests := []struct {
		name            string
		filter          *node.EncryptFilter
		testEvent       *eventlogger.Event
		setupWantEvent  func(*eventlogger.Event)
		wantEvent       *eventlogger.Event
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:   "simple",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &testPayload{
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
				e.Payload.(*testPayload).UserInfo.SensitiveUserName = string(testDecryptValue(t, wrapper, []byte(e.Payload.(*testPayload).UserInfo.SensitiveUserName)))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := tt.filter.Process(ctx, tt.testEvent)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				if tt.wantErrIs != nil {
					assert.ErrorIs(err, eventlogger.ErrInvalidParameter)
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

func testDecryptValue(t *testing.T, w wrapping.Wrapper, value []byte) []byte {
	t.Helper()
	require := require.New(t)
	value = bytes.TrimPrefix(value, []byte("encrypted:"))
	value, err := base64.RawURLEncoding.DecodeString(string(value))
	require.NoError(err)
	blobInfo := new(wrapping.EncryptedBlobInfo)
	require.NoError(proto.Unmarshal(value, blobInfo))

	marshaledInfo, err := w.Decrypt(context.Background(), blobInfo, nil)
	require.NoError(err)
	return marshaledInfo
}

type testUserInfo struct {
	PublicId          string `classified:"public"`
	SensitiveUserName string `classified:"sensitive"`
	LoginTimestamp    time.Time
}

type testPayload struct {
	NotTagged         string
	SensitiveRedacted []byte `classified:"sensitive,redact"`
	UserInfo          *testUserInfo
	Keys              [][]byte `classified:"secret"`
}
