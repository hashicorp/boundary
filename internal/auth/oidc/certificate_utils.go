// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"

	"github.com/hashicorp/boundary/internal/errors"
)

// EncodeCertificates will encode a number of x509 certificates to PEMs.
func EncodeCertificates(ctx context.Context, certs ...*x509.Certificate) ([]string, error) {
	const op = "oidc.EncodeCertificates"
	if len(certs) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no certs provided")
	}
	var pems []string
	for _, cert := range certs {
		if cert == nil {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "nil cert")
		}
		var buffer bytes.Buffer
		err := pem.Encode(&buffer, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "failed to encode cert: "+err.Error(), errors.WithWrap(err))
		}
		pems = append(pems, buffer.String())
	}
	return pems, nil
}

// ParseCertificates will parse a number of certificates PEMs to x509s.
func ParseCertificates(ctx context.Context, pems ...string) ([]*x509.Certificate, error) {
	const op = "oidc.ParseCertificates"
	if len(pems) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no PEMs provided")
	}
	var certs []*x509.Certificate
	for _, p := range pems {
		if p == "" {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "empty certificate PEM")
		}
		block, _ := pem.Decode([]byte(p))
		if block == nil {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "failed to parse certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "failed to parse certificate: "+err.Error(), errors.WithWrap(err))
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
