// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// TestKms creates a kms for testing.
func TestKms(t testing.TB, conn *db.DB, rootWrapper wrapping.Wrapper) *Kms {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	kms, err := New(context.Background(), rw, rw)
	require.NoError(err)
	err = kms.AddExternalWrappers(context.Background(), WithRootWrapper(rootWrapper))
	require.NoError(err)
	_, err = kms.underlying.GetExternalRootWrapper()
	require.NoError(err)
	return kms
}

// TestKmsDeleteKeyPurpose allows you to delete a KeyPurpose for testing.
func TestKmsDeleteKeyPurpose(t testing.TB, conn *db.DB, purpose KeyPurpose) {
	db.TestDeleteWhere(t, conn, func() any { i := dataKey{}; return &i }(), fmt.Sprintf("purpose='%s'", purpose.String()))
}

// TestKmsDeleteAllKeys allows you to delete all the keys for testing.
func TestKmsDeleteAllKeys(t testing.TB, conn *db.DB) {
	oplog.TestOplogDeleteAllEntries(t, db.New(conn).UnderlyingDB()())
	db.TestDeleteWhere(t, conn, func() any { i := rootKey{}; return &i }(), "1=1")
	db.TestDeleteWhere(t, conn, func() any { i := rootOplogKey{}; return &i }(), "1=1")
}

type dataKey struct{}

func (*dataKey) TableName() string { return "kms_data_key" }

// MockGetWrapperer provides a mock for returning a set of mock values for a
// GetWrapperer
type MockGetWrapperer struct {
	// Kms is the underlying kms which is used to provide the mock's default
	// behavior
	Kms *Kms

	// GetErr is a mock value to return for the GetWrapper(...) operation
	GetErr error

	// ReturnWrapper is a mock value to return for the GetWrapper(...) operation
	ReturnWrapper wrapping.Wrapper
}

// GetWrapper returns a wrapper for a given scope and purpose.  Supports mock
// values: ReturnWrapper, GetErr
func (m *MockGetWrapperer) GetWrapper(ctx context.Context, scopeId string, purpose KeyPurpose, opt ...Option) (wrapping.Wrapper, error) {
	switch {
	case m.ReturnWrapper != nil:
		return m.ReturnWrapper, nil
	case m.GetErr != nil:
		return nil, m.GetErr
	default:
		return m.Kms.GetWrapper(ctx, scopeId, purpose, opt...)
	}
}

// MockWrapper provides a mock for returning a set of mock values for a Wrapper
type MockWrapper struct {
	// Wrapper is the underlying wrapping.Wrapper which is used to provide the
	// mock's default behavior
	Wrapper wrapping.Wrapper

	// EncryptErr is a mock value to return for the Encrypt(...) operation
	EncryptErr error

	// DecryptErr is a mock value to return for the Decrypt(...) operation
	DecryptErr error

	// KeyIdErr is a mock value to return for the KeyId(...) operation
	KeyIdErr error

	// KeyIdReturned is a mock value to return for the KeyId(...) operation
	KeyIdReturned string
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

// / Encrypt encrypts the given byte slice and stores the resulting information
// in the returned blob info.  Mock values supported: EncryptErr
func (w *MockWrapper) Encrypt(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if w.EncryptErr != nil {
		return nil, w.EncryptErr
	}

	return w.Wrapper.Encrypt(ctx, plaintext, options...)
}

// Decrypt decrypts the given byte slice and stores the resulting information in
// the returned byte slice. Mock values supported: DecryptErr
func (w *MockWrapper) Decrypt(ctx context.Context, ciphertext *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	if w.DecryptErr != nil {
		return nil, w.DecryptErr
	}
	return w.Wrapper.Decrypt(ctx, ciphertext, options...)
}
