// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
)

func init() {
	kms.RegisterTableRewrapFn("target_proxy_certificate", proxyCertRewrapFn)
	kms.RegisterTableRewrapFn("target_alias_proxy_certificate", proxyAliasCertRewrapFn)
}

func proxyCertRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "target.proxyCertRewrapFn"
	switch {
	case dataKeyVersionId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing data key version id")
	case scopeId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	case util.IsNil(reader):
		return errors.New(ctx, errors.InvalidParameter, op, "missing database reader")
	case util.IsNil(writer):
		return errors.New(ctx, errors.InvalidParameter, op, "missing database writer")
	case kmsRepo == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing kms repository")
	}

	var certs []*TargetProxyCertificate
	if err := reader.SearchWhere(ctx, &certs, "key_id=?", []any{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, ck := range certs {
		if err := ck.Decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt proxy certificate"))
		}
		if err := ck.Encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt proxy certificate"))
		}
		if _, err := writer.Update(ctx, ck, []string{"PrivateKeyEncrypted", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to rewrap proxy certificate"))
		}
	}
	return nil
}

func proxyAliasCertRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "target.proxyAliasCertRewrapFn"
	switch {
	case dataKeyVersionId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing data key version id")
	case scopeId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	case util.IsNil(reader):
		return errors.New(ctx, errors.InvalidParameter, op, "missing database reader")
	case util.IsNil(writer):
		return errors.New(ctx, errors.InvalidParameter, op, "missing database writer")
	case kmsRepo == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing kms repository")
	}

	var certs []*TargetAliasProxyCertificate
	if err := reader.SearchWhere(ctx, &certs, "key_id=?", []any{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, ck := range certs {
		if err := ck.Decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt proxy certificate"))
		}
		if err := ck.Encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt proxy alias certificate"))
		}
		if _, err := writer.Update(ctx, ck, []string{"PrivateKeyEncrypted", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to rewrap proxy alias certificate"))
		}
	}
	return nil
}
