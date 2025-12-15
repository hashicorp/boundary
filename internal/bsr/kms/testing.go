// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
)

// TestWrapper initializes an AEAD wrapping.Wrapper for testing
func TestWrapper(t testing.TB) wrapping.Wrapper {
	t.Helper()
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}
	root := aead.NewWrapper()
	_, err = root.SetConfig(context.Background(), wrapping.WithKeyId(base64.StdEncoding.EncodeToString(rootKey)))
	if err != nil {
		t.Fatal(err)
	}
	if err := root.SetAesGcmKeyBytes(rootKey); err != nil {
		t.Fatal(err)
	}
	return root
}

// MockReader provides a mock reader for testing
type MockReader struct {
	readCount int

	// WithMockReadOn determines which read attempt the mock read results should
	// be returned on.
	WithMockReadOn int

	// WithError specifies a mock read result of the specified error
	WithError error

	// WithBytesRead specifies a mock read result of the specified bytes read
	WithBytesRead int

	// Reader is the underlying reader
	Reader io.Reader
}

// Read implements the mock read operation. Mock values supported: WithBytesRead, WithMockReadOn
func (m *MockReader) Read(p []byte) (n int, err error) {
	m.readCount++
	if m.readCount == m.WithMockReadOn {
		_, _ = m.Reader.Read(p)
		return m.WithBytesRead, m.WithError
	}
	return m.Reader.Read(p)
}

type MockWrapper struct {
	// Wrapper is the underlying wrapping.Wrapper which is used to provide the
	// mock's default behavior
	Wrapper wrapping.Wrapper

	encryptCount int

	// WithEncryptErrorOn determines which encrypt attempt the mock encrypt
	// error should be returned on.
	WithEncryptErrorOn int
	// EncryptErr is a mock value to return for the Encrypt(...) operation
	EncryptErr error

	// DecryptErr is a mock value to return for the Decrypt(...) operation
	DecryptErr error

	// KeyIdErr is a mock value to return for the KeyId(...) operation
	KeyIdErr error

	// KeyIdReturned is a mock value to return for the KeyId(...) operation
	KeyIdReturned string

	keyBytesCount int
	// WithKeyBytesErrorOn determines which key bytes attempt the mock key bytes
	// error should be returned on.
	WithKeyBytesErrorOn int
}

// Type of the wrapper.  No mock values supported
func (w *MockWrapper) Type(ctx context.Context) (wrapping.WrapperType, error) {
	return w.Wrapper.Type(ctx)
}

// KeyId is the id of the key currently used for encryption operations. Mock
// values supported: KeyIdErr, KeyIdReturned
func (w *MockWrapper) KeyId(ctx context.Context) (string, error) { // nolint
	switch {
	case w.KeyIdErr != nil:
		return "", w.KeyIdErr
	case w.KeyIdReturned != "":
		return w.KeyIdReturned, nil
	default:
		return w.Wrapper.KeyId(ctx)
	}
}

// SetConfig applies the given options to a wrapper and returns
// configuration information.  No mock values supported.
func (w *MockWrapper) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	return w.Wrapper.SetConfig(ctx, options...)
}

// Decrypt decrypts the given byte slice and stores the resulting information in
// the returned byte slice. Mock values supported: DecryptErr
func (w *MockWrapper) Decrypt(ctx context.Context, ciphertext *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	if w.DecryptErr != nil {
		return nil, w.DecryptErr
	}
	return w.Wrapper.Decrypt(ctx, ciphertext, options...)
}

// Encrypt encrypts the given byte slice. Mock values supported: EncryptErr and WithEncryptErrorOn
func (w *MockWrapper) Encrypt(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	w.encryptCount++
	if w.encryptCount == w.WithEncryptErrorOn {
		return nil, w.EncryptErr
	}
	return w.Wrapper.Encrypt(ctx, plaintext, options...)
}
