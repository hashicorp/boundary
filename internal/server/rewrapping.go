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
	// Indexes on public id, state. neither of which are queryable via scope.
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &certs, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	newKeyVersionId, err := wrapper.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to retrieve updated key version id"))
	}
	for _, cert := range certs {
		privateKey, err := decrypt(ctx, cert.PrivateKey, wrapper)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt worker auth certificate"))
		}
		if cert.PrivateKey, err = encrypt(ctx, privateKey, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt worker auth certificate"))
		}
		cert.KeyId = newKeyVersionId
		if _, err := writer.Update(ctx, cert, []string{"PrivateKey", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update worker auth certificate row with rewrapped fields"))
		}
	}
	return nil
}

func workerAuthRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "server.workerAuthRewrapFn"
	var auths []*WorkerAuth
	// An index exists on (worker_id, state), so we can query workers via scope and refine with key id.
	// This is the fastest query we can use without creating a new index on key_id.
	rows, err := reader.Query(ctx, workerAuthRewrapQuery, []interface{}{scopeId, dataKeyVersionId})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	defer rows.Close()
	for rows.Next() {
		workerAuth := allocWorkerAuth()
		if err := rows.Scan(
			&workerAuth.WorkerKeyIdentifier,
			&workerAuth.ControllerEncryptionPrivKey,
			&workerAuth.KeyId,
		); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to scan row"))
		}
		auths = append(auths, workerAuth)
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to iterate over retrieved rows"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	newKeyVersionId, err := wrapper.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to retrieve updated key version id"))
	}
	for _, workerAuth := range auths {
		privateKey, err := decrypt(ctx, workerAuth.ControllerEncryptionPrivKey, wrapper)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt worker auth"))
		}
		if workerAuth.ControllerEncryptionPrivKey, err = encrypt(ctx, privateKey, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt worker auth"))
		}
		workerAuth.KeyId = newKeyVersionId
		if _, err := writer.Update(ctx, workerAuth, []string{"ControllerEncryptionPrivKey", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update worker auth row with rewrapped fields"))
		}
	}
	return nil
}
