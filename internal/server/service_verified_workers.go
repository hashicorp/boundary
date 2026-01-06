// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// AuthorizedWorkers contain authorized worker
// public ids and unmapped worker key ids
type AuthorizedWorkers struct {
	WorkerPublicIds      []string
	UnmappedWorkerKeyIds []string
}

// VerifyKnownAndUnmappedWorkers verifies the connected worker ids and unmapped worker key ids are known to the controller
func VerifyKnownAndUnmappedWorkers(
	ctx context.Context,
	repo *Repository,
	workerAuthRepo *WorkerAuthRepositoryStorage,
	connectedWorkerIds,
	unmappedWorkerKeyIds []string,
) (*AuthorizedWorkers, error) {
	const op = "server.VerifyKnownAndUnmappedWorkers"
	switch {
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repository is required")
	case util.IsNil(workerAuthRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker auth repository is required")
	}
	var authorizedDownstreams AuthorizedWorkers
	if len(connectedWorkerIds) > 0 {
		knownConnectedWorkers, err := repo.VerifyKnownWorkers(ctx, connectedWorkerIds)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error getting known connected worker ids"))
		}
		authorizedDownstreams.WorkerPublicIds = knownConnectedWorkers
	}

	if len(unmappedWorkerKeyIds) > 0 {
		authorizedKeyIds, err := workerAuthRepo.FilterToAuthorizedWorkerKeyIds(ctx, unmappedWorkerKeyIds)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error getting authorized unmapped worker key ids"))
		}
		authorizedDownstreams.UnmappedWorkerKeyIds = authorizedKeyIds
	}
	return &authorizedDownstreams, nil
}
