// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package environmental

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/storage/storagebucketcredential"
)

type sbcHooks struct{}

func init() {
	storagebucketcredential.Register(storagebucketcredential.EnvironmentalSubtype, sbcHooks{})
}

// Vet validates that the given storagebucketcredential.StorageBucketCredential is a environmental.StorageBucketCredential
// and that it has a StorageBucketCredential store.
func (h sbcHooks) Vet(ctx context.Context, sbc storagebucketcredential.StorageBucketCredential) error {
	const op = "environmental.vet"

	sbce, ok := sbc.(*StorageBucketCredential)
	if !ok {
		return errors.New(ctx, errors.InvalidParameter, op, "StorageBucketCredential is not a sbce.StorageBucketCredential")
	}

	if sbce == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing storage bucket credential")
	}

	if sbce.StorageBucketCredentialEnvironmental == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing storage bucket credential store")
	}
	return nil
}
