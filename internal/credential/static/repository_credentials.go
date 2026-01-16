// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
func (r *Repository) Retrieve(ctx context.Context, projectId string, ids []string) ([]credential.Static, error) {
	const op = "static.(Repository).Retrieve"
	if len(ids) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no ids")
	}

	var upCreds []*UsernamePasswordCredential
	err := r.reader.SearchWhere(ctx, &upCreds, "public_id in (?)", []any{ids})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var updCreds []*UsernamePasswordDomainCredential
	err = r.reader.SearchWhere(ctx, &updCreds, "public_id in (?)", []any{ids})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var pCreds []*PasswordCredential
	err = r.reader.SearchWhere(ctx, &pCreds, "public_id in (?)", []any{ids})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var spkCreds []*SshPrivateKeyCredential
	err = r.reader.SearchWhere(ctx, &spkCreds, "public_id in (?)", []any{ids})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var jsonCreds []*JsonCredential
	err = r.reader.SearchWhere(ctx, &jsonCreds, "public_id in (?)", []any{ids})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if len(upCreds)+len(updCreds)+len(pCreds)+len(spkCreds)+len(jsonCreds) != len(ids) {
		return nil, errors.New(ctx, errors.NotSpecificIntegrity, op,
			fmt.Sprintf("mismatch between creds and number of ids requested, expected %d got %d", len(ids), len(upCreds)+len(updCreds)+len(pCreds)+len(spkCreds)+len(jsonCreds)))
	}

	out := make([]credential.Static, 0, len(ids))
	for _, c := range upCreds {
		// decrypt credential
		databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
		}
		if err := c.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		out = append(out, c)
	}

	for _, c := range updCreds {
		// decrypt credential
		databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
		}
		if err := c.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		out = append(out, c)
	}

	for _, c := range pCreds {
		// decrypt credential
		databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
		}
		if err := c.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		out = append(out, c)
	}

	for _, c := range spkCreds {
		// decrypt credential
		databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
		}
		if err := c.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		out = append(out, c)
	}

	for _, c := range jsonCreds {
		// decrypt credential
		databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
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
