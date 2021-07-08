package servers

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

// TestRepo creates a repo that can be used for various purposes.
// Crucially, it ensures that the global scope contains a valid root
// key.
func TestRepo(t *testing.T, conn *gorm.DB, rootWrapper wrapping.Wrapper) *Repository {
	require := require.New(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	wrapper, err := kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		_, err = kms.CreateKeysTx(context.Background(), rw, rw, rootWrapper, rand.Reader, scope.Global.String())
		require.NoError(err)
		wrapper, err = kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeOplog)
		if err != nil {
			panic(err)
		}
	}
	require.NoError(err)
	require.NotNil(wrapper)

	repo, err := NewRepository(rw, rw, kmsCache)
	require.NoError(err)
	return repo
}
