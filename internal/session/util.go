// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"crypto/ed25519"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// DeriveED25519Key generates a key based on the project's session DEK, the
// requesting user, and the generated job ID.
func DeriveED25519Key(ctx context.Context, wrapper wrapping.Wrapper, userId, jobId string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	const op = "session.DeriveED25519Key"
	var uId, jId []byte
	if userId != "" {
		uId = []byte(userId)
	}
	if jobId != "" {
		jId = []byte(jobId)
	}
	if wrapper == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing wrapper")
	}

	reader, err := crypto.NewDerivedReader(ctx, wrapper, 32, uId, jId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return ed25519.GenerateKey(reader)
}
