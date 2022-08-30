package server

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/server/store"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
)

// WorkerAuthActivationToken contains an activation token for a worker
type WorkerAuthActivationToken struct {
	*store.WorkerAuthActivationToken
	tableName string `gorm:"-"`
}

func newWorkerAuthActivationToken(ctx context.Context, workerId, tokenId, activationToken string, _ ...Option) (*WorkerAuthActivationToken, error) {
	const op = "server.newWorkerAuthActivationToken"

	switch {
	case workerId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no worker id")
	case tokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no token id")
	case activationToken == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no activation token")
	}

	l := &WorkerAuthActivationToken{
		WorkerAuthActivationToken: &store.WorkerAuthActivationToken{
			WorkerId:        workerId,
			TokenId:         tokenId,
			ActivationToken: []byte(activationToken),
		},
	}

	return l, nil
}

func allocWorkerAuthActivationToken() *WorkerAuthActivationToken {
	return &WorkerAuthActivationToken{
		WorkerAuthActivationToken: &store.WorkerAuthActivationToken{},
	}
}

func (w *WorkerAuthActivationToken) clone() *WorkerAuthActivationToken {
	cp := proto.Clone(w.WorkerAuthActivationToken)
	return &WorkerAuthActivationToken{
		WorkerAuthActivationToken: cp.(*store.WorkerAuthActivationToken),
	}
}

// ValidateNewWorkerAuthActivationToken is called before storing a WorkerAuthActivationToken in the db
func (w *WorkerAuthActivationToken) ValidateNewWorkerAuthActivationToken(ctx context.Context) error {
	const op = "server.(WorkerAuthActivationToken).ValidateNewWorkerAuthActivationToken"
	if w.WorkerId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing worker id")
	}
	if w.TokenId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing token id")
	}
	if len(w.ActivationTokenEncrypted) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing encrypted activation token")
	}

	return nil
}

// TableName returns the table name.
func (w *WorkerAuthActivationToken) TableName() string {
	if w.tableName != "" {
		return w.tableName
	}
	return "worker_auth_activation_token"
}

// SetTableName sets the table name.
func (w *WorkerAuthActivationToken) SetTableName(n string) {
	w.tableName = n
}

// encrypt the activation token before storing
func (w *WorkerAuthActivationToken) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "server.(WorkerAuthActivationToken).encrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, w.WorkerAuthActivationToken); err != nil {
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
func (w *WorkerAuthActivationToken) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "server.(WorkerAuthActivationToken).decrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.UnwrapStruct(ctx, cipher, w.WorkerAuthActivationToken); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
