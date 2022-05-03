package kms

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
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
	db.TestDeleteWhere(t, conn, func() interface{} { i := dataKey{}; return &i }(), fmt.Sprintf("purpose='%s'", purpose.String()))
}

// TestKmsDeleteAllKeys allows you to delete all the keys for testing.
func TestKmsDeleteAllKeys(t testing.TB, conn *db.DB) {
	db.TestDeleteWhere(t, conn, func() interface{} { i := rootKey{}; return &i }(), "1=1")
}

type dataKey struct{}

func (*dataKey) TableName() string { return "kms_data_key" }
