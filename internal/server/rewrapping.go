package server

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

func init() {
	kms.RegisterTableRewrapFn("worker_auth_ca_certificate", workerAuthCertRewrapFn)
	kms.RegisterTableRewrapFn("worker_auth_authorized", workerAuthRewrapFn)
}

func workerAuthCertRewrapFn(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "server.workerAuthCertRewrapFn"
	var certs []*RootCertificate
	// indexes on public id, state. neither of which are queryable via scope. this is the fastest query
	if err := reader.SearchWhere(ctx, &certs, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
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
		if cert.PrivateKey, err = encrypt(ctx, privateKey, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		cert.KeyId = newKeyVersionId
		if _, err := writer.Update(ctx, cert, []string{"PrivateKey", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

func workerAuthRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "server.workerAuthRewrapFn"
	var auths []*WorkerAuth
	// an index exists on (worker_id, state), so we can query workers via scope and refine with key id. this is the fastest query
	rows, err := reader.Query(ctx, workerAuthRewrapQuery, []interface{}{dataKeyVersionId, scopeId})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for rows.Next() {
		workerAuth := allocWorkerAuth()
		if err := rows.Scan(
			&workerAuth.WorkerKeyIdentifier,
			&workerAuth.ControllerEncryptionPrivKey,
			&workerAuth.KeyId,
		); err != nil {
			_ = rows.Close()
			return errors.Wrap(ctx, err, op)
		}
		auths = append(auths, workerAuth)
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	newKeyVersionId, err := wrapper.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, workerAuth := range auths {
		privateKey, err := decrypt(ctx, workerAuth.ControllerEncryptionPrivKey, wrapper)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if workerAuth.ControllerEncryptionPrivKey, err = encrypt(ctx, privateKey, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		workerAuth.KeyId = newKeyVersionId
		if _, err := writer.Update(ctx, workerAuth, []string{"ControllerEncryptionPrivKey", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}
