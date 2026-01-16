// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/util"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

const (
	CtCertificateKeyField = "CtCertificateKey"
	CtPasswordField       = "CtPassword"
	KeyIdField            = "KeyId"
)

func init() {
	kms.RegisterTableRewrapFn(clientCertificateTableName, clientCertificateRewrapFn)
	kms.RegisterTableRewrapFn(bindCredentialTableName, bindCredentialRewrapFn)
}

// hmacField simply hmac's a field in a consistent manner for this pkg
func hmacField(ctx context.Context, cipher wrapping.Wrapper, field []byte, publicId string) ([]byte, error) {
	const op = "ldap.hmacField"
	hm, err := crypto.HmacSha256(ctx, field, cipher, []byte(publicId), nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return []byte(hm), nil
}

// bindCredentialRewrapFn provides a kms.Rewrapfn for the BindCredential type
func bindCredentialRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "ldap.bindCredentialRewrapFn"
	if dataKeyVersionId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing data key version id")
	}
	if scopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if util.IsNil(reader) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing database reader")
	}
	if util.IsNil(writer) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing database writer")
	}
	if util.IsNil(kmsRepo) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing kms repository")
	}
	var creds []*BindCredential
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &creds, "key_id=?", []any{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, cc := range creds {
		if err := cc.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt bind credential"))
		}
		if err := cc.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt bind credential"))
		}
		if _, err := writer.Update(ctx, cc, []string{CtPasswordField, KeyIdField}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update bind credential row with rewrapped fields"))
		}
	}
	return nil
}

// clientCertificateRewrapFn provides a kms.Rewrapfn for the ClientCertificate type
func clientCertificateRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "ldap.clientCertificateRewrapFn"
	if dataKeyVersionId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing data key version id")
	}
	if scopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if util.IsNil(reader) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing database reader")
	}
	if util.IsNil(writer) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing database writer")
	}
	if kmsRepo == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing kms repository")
	}
	var clientCerts []*ClientCertificate
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &clientCerts, "key_id=?", []any{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, cc := range clientCerts {
		if err := cc.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt client certificate"))
		}
		if err := cc.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt client certificate"))
		}
		if _, err := writer.Update(ctx, cc, []string{CtCertificateKeyField, KeyIdField}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update client certificate row with rewrapped fields"))
		}
	}
	return nil
}
