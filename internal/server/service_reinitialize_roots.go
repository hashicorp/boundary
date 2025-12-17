// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
)

// ReinitializeRoots is a domain service function that removes both root certificates and then
// calls RotateRoots to generate new root certificates.
// Accepts the nodeenrollment option, WithCertificateLifetime(time.Duration) to specify the lifetime
// of the generated cert(s)
func ReinitializeRoots(ctx context.Context, workerAuthRepo *WorkerAuthRepositoryStorage, opt ...nodeenrollment.Option) (*types.RootCertificates, error) {
	const op = "server.ReinitializeRoots"
	if workerAuthRepo == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing workerAuthRepo")
	}

	// Use WithReinitializeRoots to ensure existing roots are removed before rotation
	opt = append(opt, nodeenrollment.WithReinitializeRoots(true))
	roots, err := RotateRoots(ctx, workerAuthRepo, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return roots, nil
}
