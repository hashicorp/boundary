package server

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/types"
)

// RotateRoots is a domain service function that initiates a rotation of root certificates
// via a call to the nodenenrollment RotateRootCertificates function
// Accepts the nodeenrollment option, WithCertificateLifetime(time.Duration) to specify the lifetime
// of the generated cert(s)
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
	opt = append(opt, nodeenrollment.WithState(rootCerts.GetState()))

	roots, err := rotation.RotateRootCertificates(ctx, workerAuthRepo, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return roots, nil
}
