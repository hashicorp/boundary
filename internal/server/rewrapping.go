// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
)

func init() {
	kms.RegisterTableRewrapFn("worker_auth_ca_certificate", workerAuthCertRewrapFn)
	kms.RegisterTableRewrapFn("worker_auth_authorized", workerAuthRewrapFn)
	kms.RegisterTableRewrapFn("worker_auth_server_led_activation_token", workerAuthServerLedActivationTokenRewrapFn)
}

func rewrapParameterChecks(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) string {
	if dataKeyVersionId == "" {
		return "missing data key version id"
	}
	if scopeId == "" {
		return "missing scope id"
	}
	if util.IsNil(reader) {
		return "missing database reader"
	}
	if util.IsNil(writer) {
		return "missing database writer"
	}
	if kmsRepo == nil {
		return "missing kms repository"
	}
	return ""
}

func workerAuthCertRewrapFn(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "server.workerAuthCertRewrapFn"
	if errStr := rewrapParameterChecks(ctx, dataKeyVersionId, scopeId, reader, writer, kmsRepo); errStr != "" {
		return errors.New(ctx, errors.InvalidParameter, op, errStr)
	}
	var certs []*RootCertificate
	// Indexes on public id, state. neither of which are queryable via scope.
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &certs, "key_id=?", []any{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, cert := range certs {
		if err := cert.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt worker auth certificate"))
		}
		if err := cert.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt worker auth certificate"))
		}
		if _, err := writer.Update(ctx, cert, []string{"CtPrivateKey", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update worker auth certificate row with rewrapped fields"))
		}
	}
	return nil
}

func workerAuthRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "server.workerAuthRewrapFn"
	if errStr := rewrapParameterChecks(ctx, dataKeyVersionId, scopeId, reader, writer, kmsRepo); errStr != "" {
		return errors.New(ctx, errors.InvalidParameter, op, errStr)
	}
	var auths []*WorkerAuth
	// An index exists on (worker_id, state), so we can query workers via scope and refine with key id.
	// This is the fastest query we can use without creating a new index on key_id.
	rows, err := reader.Query(ctx, workerAuthRewrapQuery, []any{scopeId, dataKeyVersionId})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	defer rows.Close()
	for rows.Next() {
		workerAuth := allocWorkerAuth()
		if err := rows.Scan(
			&workerAuth.WorkerKeyIdentifier,
			&workerAuth.CtControllerEncryptionPrivKey,
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
	for _, workerAuth := range auths {
		if err := workerAuth.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt worker auth"))
		}
		if err := workerAuth.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt worker auth"))
		}
		if _, err := writer.Update(ctx, workerAuth, []string{"CtControllerEncryptionPrivKey", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update worker auth row with rewrapped fields"))
		}
	}
	return nil
}

func workerAuthServerLedActivationTokenRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "server.workerAuthServerLedActivationTokenRewrapFn"
	if errStr := rewrapParameterChecks(ctx, dataKeyVersionId, scopeId, reader, writer, kmsRepo); errStr != "" {
		return errors.New(ctx, errors.InvalidParameter, op, errStr)
	}
	var tokens []*WorkerAuthServerLedActivationToken
	// An index exists on worker_id, so we can query workers via scope and refine with key id.
	// This is the fastest query we can use without creating a new index on key_id.
	rows, err := reader.Query(ctx, workerAuthServerLedActivationTokenRewrapQuery, []any{scopeId, dataKeyVersionId})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	defer rows.Close()
	for rows.Next() {
		token := allocWorkerAuthServerLedActivationToken()
		if err := rows.Scan(
			&token.WorkerId,
			&token.CreationTimeEncrypted,
			&token.KeyId,
		); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to scan row"))
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to iterate over retrieved rows"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, token := range tokens {
		if err := token.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt activation token"))
		}
		if err := token.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt activation token"))
		}
		if _, err := writer.Update(ctx, token, []string{"CreationTimeEncrypted", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update activation token row with rewrapped fields"))
		}
	}
	return nil
}
