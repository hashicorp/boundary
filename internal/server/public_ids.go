// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

func newWorkerId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.WorkerPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "server.newWorkerId")
	}
	return id, nil
}

// NewWorkerIdFromScopeAndName generates a predictable public id based on the
// scope and the worker name.  This should only be used on kms workers at
// upsert time.
func NewWorkerIdFromScopeAndName(ctx context.Context, scope, name string) (string, error) {
	const op = "server.NewWorkerIdFromScopeAndName"
	id, err := db.NewPublicId(ctx, globals.WorkerPrefix, db.WithPrngValues([]string{scope, name}))
	if err != nil {
		return "", errors.Wrap(ctx, err, "server.newWorkerId")
	}
	return id, nil
}
