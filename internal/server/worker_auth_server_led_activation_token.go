// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/server/store"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
)

// WorkerAuthServerLedActivationToken contains an activation token for a worker
type WorkerAuthServerLedActivationToken struct {
	*store.WorkerAuthServerLedActivationToken
	tableName string `gorm:"-"`
}

// newWorkerAuthServerLedActivation creates a new token from the given values
func newWorkerAuthServerLedActivationToken(ctx context.Context, workerId, tokenId string, creationTime []byte, _ ...Option) (*WorkerAuthServerLedActivationToken, error) {
	const op = "server.newWorkerAuthServerLedActivationToken"

	switch {
	case workerId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no worker id")
	case tokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no token id")
	case len(creationTime) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty creation time")
	}

	l := &WorkerAuthServerLedActivationToken{
		WorkerAuthServerLedActivationToken: &store.WorkerAuthServerLedActivationToken{
			WorkerId:     workerId,
			TokenId:      tokenId,
			CreationTime: creationTime,
		},
	}

	return l, nil
}

func allocWorkerAuthServerLedActivationToken() *WorkerAuthServerLedActivationToken {
	return &WorkerAuthServerLedActivationToken{
		WorkerAuthServerLedActivationToken: &store.WorkerAuthServerLedActivationToken{},
	}
}

func (w *WorkerAuthServerLedActivationToken) clone() *WorkerAuthServerLedActivationToken {
	cp := proto.Clone(w.WorkerAuthServerLedActivationToken)
	return &WorkerAuthServerLedActivationToken{
		WorkerAuthServerLedActivationToken: cp.(*store.WorkerAuthServerLedActivationToken),
	}
}

// ValidateNewWorkerAuthServerLedActivationToken is called before storing a WorkerAuthActivationToken in the db
func (w *WorkerAuthServerLedActivationToken) ValidateNewWorkerAuthServerLedActivationToken(ctx context.Context) error {
	const op = "server.(WorkerAuthServerLedActivationToken).ValidateNewWorkerAuthServerLedActivationToken"
	if w.WorkerId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing worker id")
	}
	if w.TokenId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing token id")
	}
	if len(w.CreationTimeEncrypted) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing encrypted creation time")
	}

	return nil
}

// TableName returns the table name.
func (w *WorkerAuthServerLedActivationToken) TableName() string {
	if w.tableName != "" {
		return w.tableName
	}
	return "worker_auth_server_led_activation_token"
}

// SetTableName sets the table name.
func (w *WorkerAuthServerLedActivationToken) SetTableName(n string) {
	w.tableName = n
}

// encrypt the activation token before storing
func (w *WorkerAuthServerLedActivationToken) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "server.(WorkerAuthServerLedActivationToken).encrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, w.WorkerAuthServerLedActivationToken); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to read cipher key id"))
	}
	w.KeyId = keyId

	return nil
}

// decrypt the auth method after reading it from the db
func (w *WorkerAuthServerLedActivationToken) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "server.(WorkerAuthServerLedActivationToken).decrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.UnwrapStruct(ctx, cipher, w.WorkerAuthServerLedActivationToken); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
