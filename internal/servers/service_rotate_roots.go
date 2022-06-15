package servers

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/rotation"
)

// RotateRoots is a domain service function that initiates a rotation of root certificates
// via a call to the nodenenrollment RotateRootCertificates function
// Accepts the nodeenrollment option, WithCertificateLifetime(time.Duration) to specify the lifetime
// of the generated cert(s)
func RotateRoots(ctx context.Context, workerAuthRepo *WorkerAuthRepositoryStorage, opt ...nodeenrollment.Option) error {
	const op = "servers.RotateRoots"
	if workerAuthRepo == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing workerAuthRepo")
	}

	_, err := rotation.RotateRootCertificates(ctx, workerAuthRepo, opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}
