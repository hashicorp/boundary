// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"context"

	"github.com/hashicorp/boundary/internal/libs/crypto"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

type signer func(context.Context, []byte) (string, error)

func newSigner(_ context.Context, w wrapping.Wrapper, info, salt []byte) (signer, error) {
	const op = "event.hmacHclogSigner"
	return func(requestCtx context.Context, data []byte) (string, error) {
		return crypto.HmacSha256(requestCtx, data, w, info, salt, crypto.WithPrefix("hmac-sha256:"), crypto.WithBase64Encoding())
	}, nil
}
