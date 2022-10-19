package server

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
)

func init() {
	kms.RegisterTableRewrapFn("worker_auth_ca_certificate", workerAuthCertRewrapFn)
}

func workerAuthCertRewrapFn(ctx context.Context, dataKeyVersionId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "server.workerAuthCertRewrapFn"
	repo, err := NewRepository(reader, writer, kmsRepo)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	var certs []*RootCertificate
	if err := repo.reader.SearchWhere(ctx, &certs, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	wrapper, err := repo.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	newKeyVersionId, err := wrapper.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, cert := range certs {
		privateKey, err := decrypt(ctx, cert.PrivateKey, wrapper)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		ctPrivateKey, err := encrypt(ctx, privateKey, wrapper)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		cert.KeyId = newKeyVersionId
		cert.PrivateKey = ctPrivateKey
		if _, err := repo.writer.Update(ctx, cert, []string{"PrivateKey", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}
