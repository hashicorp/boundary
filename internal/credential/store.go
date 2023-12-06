// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential/store"
	"github.com/hashicorp/boundary/internal/errors"
)

// StoreListQueryResult describes the result from the
// credential store list query used to list all credential
// store subtypes.
type StoreListQueryResult struct {
	*store.StoreListQueryResult
}

func (s *StoreListQueryResult) toStore(ctx context.Context) (Store, error) {
	const op = "credential.(*StoreListQueryResult).storeSubtype"

	newFn, ok := subtypeRegistry.newFunc(globals.Subtype(s.Subtype))
	if !ok {
		return nil, errors.New(ctx,
			errors.InvalidParameter,
			op,
			fmt.Sprintf("%s is an unknown credential store subtype of %s", s.PublicId, s.Subtype),
		)
	}

	return newFn(ctx, s)
}
