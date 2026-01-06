// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/types"
)

// RotateRoots is a domain service function that initiates a rotation of root
// certificates via a call to the nodenenrollment RotateRootCertificates
// function. Accepts the nodeenrollment option
// WithCertificateLifetime(time.Duration) to specify the lifetime of the
// generated cert(s).
func RotateRoots(ctx context.Context, workerAuthRepo *WorkerAuthRepositoryStorage, opt ...nodeenrollment.Option) (*types.RootCertificates, error) {
	const op = "server.RotateRoots"
	if workerAuthRepo == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing workerAuthRepo")
	}

	// Get current root certs so we can pass along the version
	rootCerts := &types.RootCertificates{Id: CaId}
	err := workerAuthRepo.Load(ctx, rootCerts)
	if err != nil && err != nodeenrollment.ErrNotFound {
		return nil, errors.Wrap(ctx, err, op)
	}
	opt = append(opt,
		nodeenrollment.WithState(rootCerts.GetState()),
	)

	var current, next string
	if rootCerts.Current != nil {
		current = rootCerts.Current.GetId()
	}
	if rootCerts.Next != nil {
		next = rootCerts.Next.GetId()
	}

	roots, err := rotation.RotateRootCertificates(ctx, workerAuthRepo, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if roots != nil && (roots.Current.GetId() != current || roots.Next.GetId() != next) {
		var args []any
		currentKeyId, err := nodeenrollment.KeyIdFromPkix(roots.Current.PublicKeyPkix)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error deriving pkix string from current ca certificate public key after rotation: %w", err))
		} else {
			args = append(args,
				"current_ca_cert_id", currentKeyId,
				"current_ca_cert_not_before", roots.Current.GetNotBefore().AsTime().Format(time.RFC3339),
				"current_ca_cert_not_after", roots.Current.GetNotAfter().AsTime().Format(time.RFC3339),
			)
		}
		nextKeyId, err := nodeenrollment.KeyIdFromPkix(roots.Next.PublicKeyPkix)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error deriving pkix string from next ca certificate public key after rotation: %w", err))
		} else {
			args = append(args,
				"next_ca_cert_id", nextKeyId,
				"next_ca_cert_not_before", roots.Next.GetNotBefore().AsTime().Format(time.RFC3339),
				"next_ca_cert_not_after", roots.Next.GetNotAfter().AsTime().Format(time.RFC3339),
			)
		}
		event.WriteSysEvent(ctx, op, "worker auth root certificates were rotated", args...)

	}

	return roots, nil
}
