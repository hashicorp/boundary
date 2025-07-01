// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package encrypt

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"testing"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// TestWrapper initializes an AEAD wrapping.Wrapper for testing
func TestWrapper(t *testing.T) wrapping.Wrapper {
	t.Helper()
	require := require.New(t)
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	require.NoErrorf(err, "unable to read random data for test wrapper")
	require.Equalf(n, 32, "random data for test wrapper is not the proper length of 32 bytes")

	root := aead.NewWrapper()
	_, err = root.SetConfig(
		context.Background(),
		wrapping.WithKeyId(base64.StdEncoding.EncodeToString(rootKey)),
	)
	require.NoErrorf(err, "unable to encode key for wrapper")

	err = root.SetAesGcmKeyBytes(rootKey)
	require.NoErrorf(err, "unable to set wrapper's key bytes")

	return root
}

func TestDecryptValue(t *testing.T, w wrapping.Wrapper, value []byte) []byte {
	t.Helper()
	require := require.New(t)
	require.NotNilf(w, "wrapper is missing")
	value = bytes.TrimPrefix(value, []byte("encrypted:"))
	value, err := base64.RawURLEncoding.DecodeString(string(value))
	require.NoError(err)
	blobInfo := new(wrapping.BlobInfo)
	require.NoError(proto.Unmarshal(value, blobInfo))

	if blobInfo.Ciphertext == nil {
		return nil
	}
	marshaledInfo, err := w.Decrypt(context.Background(), blobInfo, nil)
	require.NoError(err)
	return marshaledInfo
}

func TestHmacSha256(t *testing.T, data []byte, w wrapping.Wrapper, salt, info []byte) string {
	t.Helper()
	require := require.New(t)
	reader, err := NewDerivedReader(context.Background(), w, 32, salt, info)
	require.NoError(err)

	key := make([]byte, 32)
	n, err := io.ReadFull(reader, key)
	require.NoError(err)
	require.Equal(32, n)

	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return "hmac-sha256:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// TestMapField defines a const for a field name used for testing TestTaggedMap
const TestMapField = "foo"

const TestPublicMapField = "public-foo"

// TestTaggedMap is a map that implements the Taggable interface for testing
type TestTaggedMap map[string]interface{}

// Tags implements the taggable interface for the TestTaggedMap type
func (t TestTaggedMap) Tags() ([]PointerTag, error) {
	return []PointerTag{
		{
			Pointer:        "/" + TestMapField,
			Classification: SecretClassification,
			Filter:         RedactOperation,
		},
		{
			Pointer:        "/" + TestPublicMapField,
			Classification: PublicClassification,
			Filter:         NoOperation,
		},
	}, nil
}

type testUserInfo struct {
	PublicId          string `class:"public"`
	SensitiveUserName string `class:"sensitive"`
	LoginTimestamp    time.Time
}

type testPayload struct {
	notExported       string
	NotTagged         string
	SensitiveRedacted []byte `class:"sensitive,redact"`
	UserInfo          *testUserInfo
	Keys              [][]byte `class:"secret"`
}
