package static

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

// Retrieve retrieves and returns static credentials from Boundary for all the provided
// ids. All the returned static credentials will have their secret fields decrypted.
func (r *Repository) Retrieve(ctx context.Context, scopeId string, ids []string) ([]credential.Static, error) {
	const op = "static.(Repository).Retrieve"
	if len(ids) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no ids")
	}

	var creds []*UsernamePasswordCredential
	err := r.reader.SearchWhere(ctx, &creds, "public_id in (?)", []interface{}{ids})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(creds) != len(ids) {
		return nil, errors.New(ctx, errors.NotSpecificIntegrity, op,
			fmt.Sprintf("mismatch between creds and number of ids requested, expected %d got %d", len(ids), len(creds)))
	}

	out := make([]credential.Static, 0, len(ids))
	for _, c := range creds {
		// decrypt credential
		databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
		}
		if err := c.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		out = append(out, c)
	}

	return out, nil
}
