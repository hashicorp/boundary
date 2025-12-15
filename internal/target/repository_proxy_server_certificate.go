// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/globals"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

type proxyServerCertificate interface {
	Decrypt(ctx context.Context, wrapper wrapping.Wrapper) error
	Encrypt(ctx context.Context, wrapper wrapping.Wrapper) error
	GetNotValidAfter() *timestamp.Timestamp
	SetPrivateKey(privKeyBytes []byte)
	SetPublicKey(pubKeyBytes []byte)
	SetCertificate(certBytes []byte)
	SetNotValidAfter(timestamp *timestamp.Timestamp)
	ToServerCertificate(ctx context.Context) (*ServerCertificate, error)
}

// Check if the certificate is close to expiration and regenerate/ update it if necessary.
func maybeRegenerateCert(ctx context.Context, t proxyServerCertificate, w db.Writer, wrapper wrapping.Wrapper, sessionMaxSeconds uint32, opt ...Option) (*ServerCertificate, error) {
	const op = "target.maybeRegenerateCert"
	switch {
	case wrapper == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "wrapper is nil")
	case t == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "target is nil")
	case util.IsNil(w):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case sessionMaxSeconds == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "session max seconds is 0")
	}

	// Check if the certificate is close to expiration. We consider it close to expiration if it is less than 1 day + sessionMaxSeconds away from now.
	if t.GetNotValidAfter().AsTime().Before(time.Now().Add((time.Hour * 24) + (time.Second * time.Duration(sessionMaxSeconds)))) {
		notValidAfter := time.Now().AddDate(1, 0, 0) // 1 year from now

		privKey, pubKey, cert, err := generateKeysAndCert(ctx, notValidAfter, opt...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error generating keys and certificate for proxy server certificate"))
		}
		t.SetPrivateKey(privKey)
		t.SetPublicKey(pubKey)
		t.SetCertificate(cert)
		t.SetNotValidAfter(timestamp.New(notValidAfter))

		if err := t.Encrypt(ctx, wrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error encrypting proxy certificate"))
		}

		var rowsUpdated int
		rowsUpdated, err = w.Update(ctx, t, []string{"PublicKey", "PrivateKey", "Certificate", "NotValidAfter"}, nil)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error updating proxy server certificate"))
		}
		if rowsUpdated != 1 {
			return nil, errors.New(ctx, errors.MultipleRecords, op, "more than 1 proxy server certificate would have been updated")
		}
	}

	if err := t.Decrypt(ctx, wrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to decrypt proxy server certificate private key"))
	}

	serverCert, err := t.ToServerCertificate(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error converting proxy server certificate to PEM"))
	}

	return serverCert, nil
}

func fetchTargetProxyServerCertificate(ctx context.Context, r db.Reader, w db.Writer, targetId, scopeId string, wrapper wrapping.Wrapper, sessionMaxSeconds uint32) (*ServerCertificate, error) {
	const op = "target.fetchTargetProxyServerCert"
	switch {
	case wrapper == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "wrapper is nil")
	case util.IsNil(r):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "reader is nil")
	case util.IsNil(w):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case targetId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "target id is empty")
	case scopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "scope id is empty")
	}

	targetCert := allocTargetProxyCertificate()
	if err := r.SearchWhere(ctx, &targetCert, "target_id = ?", []any{targetId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// If a cert is not found, this target type does not support proxy server certificates/ it was not generated during target creation.
	if targetCert.Certificate == nil {
		return nil, errors.New(ctx, errors.RecordNotFound, op, "target proxy server certificate not found", errors.WithoutEvent())
	}

	return maybeRegenerateCert(ctx, targetCert, w, wrapper, sessionMaxSeconds)
}

func fetchTargetAliasProxyServerCertificate(ctx context.Context, r db.Reader, w db.Writer, targetId, scopeId string, alias *talias.Alias, wrapper wrapping.Wrapper, sessionMaxSeconds uint32, opt ...Option) (*ServerCertificate, error) {
	const op = "target.fetchTargetProxyServerCert"
	switch {
	case wrapper == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "wrapper is nil")
	case util.IsNil(r):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "reader is nil")
	case util.IsNil(w):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case alias == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "alias is nil")
	case alias.Value == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "alias value is empty")
	case targetId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "target id is empty")
	case scopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "scope id is empty")
	}

	// We first check if a localhost cert exists for this target; if it does not, one was not generated during
	// target creation because it is not applicable and we don't need an alias proxy cert.
	targetCert := allocTargetProxyCertificate()
	if err := r.SearchWhere(ctx, &targetCert, "target_id = ?", []any{targetId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if targetCert.Certificate == nil {
		return nil, errors.New(ctx, errors.RecordNotFound, op, "target proxy server certificate not found", errors.WithoutEvent())
	}

	aliasCert := allocTargetAliasProxyCertificate()
	if err := r.SearchWhere(ctx, &aliasCert, "target_id = ? and alias_id = ?", []any{targetId, alias.PublicId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// Create the cert, if not found- alias certs are not created as part of target creation.
	var err error
	if aliasCert.Certificate == nil {
		aliasCert, err = NewTargetAliasProxyCertificate(ctx, targetId, alias, opt...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating new target alias proxy certificate"))
		}
		if err = aliasCert.Encrypt(ctx, wrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error encrypting target alias proxy certificate"))
		}
		id, err := db.NewPublicId(ctx, globals.ProxyServerCertificatePrefix)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		aliasCert.PublicId = id
		if err = w.Create(ctx, aliasCert); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create target alias proxy certificate"))
		}
	}

	return maybeRegenerateCert(ctx, aliasCert, w, wrapper, sessionMaxSeconds, WithAlias(alias))
}
