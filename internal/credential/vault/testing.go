package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialStores creates count number of vault credential stores in
// the provided DB with the provided scope id. If any errors are
// encountered during the creation of the credential stores, the test will
// fail.
func TestCredentialStores(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, scopeId string, count int) []*CredentialStore {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)
	var css []*CredentialStore
	for i := 0; i < count; i++ {

		cs, err := NewCredentialStore(scopeId, fmt.Sprintf("http://vault%d", i), []byte(fmt.Sprintf("token%d", i)))
		assert.NoError(err)
		require.NotNil(cs)
		id, err := newCredentialStoreId()
		assert.NoError(err)
		require.NotEmpty(id)
		cs.PublicId = id

		ctx := context.Background()
		_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, iw db.Writer) error {
				return iw.Create(ctx, cs)
			},
		)

		require.NoError(err2)
		css = append(css, cs)
	}
	return css
}
