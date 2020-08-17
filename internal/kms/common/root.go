package common

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateRootKeyTx inserts into the db (via db.Writer) and returns the new root
// key and root key version.  This function encapsulates all the work required
// within a db.TxHandler and allows this capability to be shared with the iam
// repo via a common pkg without circular dependencies
func CreateRootKeyTx(ctx context.Context, w db.Writer, keyWrapper wrapping.Wrapper, scopeId string, key []byte) (*kms.RootKey, *kms.RootKeyVersion, error) {
	return kms.CreateRootKeyTx(ctx, w, keyWrapper, scopeId, key)
}
