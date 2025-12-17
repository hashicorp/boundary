// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/server/store"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
)

const (
	previousWorkerAuthState = "previous"
	currentWorkerAuthState  = "current"
)

// WorkerAuth contains all fields related to an authorized Worker resource
// This includes worker public keys, the controller encryption key,
// and certificate bundles issued by the Boundary CA
type WorkerAuth struct {
	*store.WorkerAuth
	tableName string `gorm:"-"`
}

func (w *WorkerAuth) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "server.(WorkerAuth).encrypt"
	if len(w.ControllerEncryptionPrivKey) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "no private key provided")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, w.WorkerAuth, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("error reading cipher key id"))
	}
	w.KeyId = keyId
	return nil
}

func (w *WorkerAuth) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "server.(WorkerAuth).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, w.WorkerAuth, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

func (w *WorkerAuth) compare(other *WorkerAuth) bool {
	switch {
	case w.WorkerId != other.WorkerId:
		return false
	case !bytes.Equal(w.WorkerEncryptionPubKey, other.WorkerEncryptionPubKey):
		return false
	case !bytes.Equal(w.WorkerSigningPubKey, other.WorkerSigningPubKey):
		return false
	case !bytes.Equal(w.Nonce, other.Nonce):
		return false
	default:
		return true
	}
}

// WorkerAuthSet is intended to store a set of WorkerAuth records
// This set represents the current and previous WorkerAuth records for a worker
type WorkerAuthSet struct {
	Previous *WorkerAuth
	Current  *WorkerAuth
}

// WorkerKeys contain the signing and encryption keys for a WorkerAuth resource
type WorkerKeys struct {
	workerSigningPubKey    []byte
	workerEncryptionPubKey []byte
}

// newWorkerAuth initializes a new in-memory WorkerAuth struct.
// supported options:
// - withWorkerKeys
// - withControllerEncryptionPrivateKey (assigns the value to the plain-text field)
// - withNonce
func newWorkerAuth(ctx context.Context, workerKeyIdentifier, workerId string, opt ...Option) (*WorkerAuth, error) {
	const op = "server.newWorkerAuth"
	opts := GetOpts(opt...)

	if workerKeyIdentifier == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no workerKeyIdentifier")
	}
	if workerId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no workerId")
	}

	l := &WorkerAuth{
		WorkerAuth: &store.WorkerAuth{
			WorkerKeyIdentifier: workerKeyIdentifier,
			WorkerId:            workerId,
		},
	}

	if len(opts.withWorkerKeys.workerSigningPubKey) != 0 &&
		len(opts.withWorkerKeys.workerEncryptionPubKey) != 0 {
		l.WorkerSigningPubKey = opts.withWorkerKeys.workerSigningPubKey
		l.WorkerEncryptionPubKey = opts.withWorkerKeys.workerEncryptionPubKey
	}
	if len(opts.withControllerEncryptionPrivateKey) != 0 {
		l.ControllerEncryptionPrivKey = opts.withControllerEncryptionPrivateKey
	}
	if opts.withNonce != nil {
		l.Nonce = opts.withNonce
	}
	return l, nil
}

func allocWorkerAuth() *WorkerAuth {
	return &WorkerAuth{
		WorkerAuth: &store.WorkerAuth{},
	}
}

func (w *WorkerAuth) clone() *WorkerAuth {
	cp := proto.Clone(w.WorkerAuth)
	return &WorkerAuth{
		WorkerAuth: cp.(*store.WorkerAuth),
	}
}

// Validate is called before storing a WorkerAuth in the db
func (w *WorkerAuth) ValidateNewWorkerAuth(ctx context.Context) error {
	const op = "server.(WorkerAuth).validateNewWorkerAuth"
	if w.WorkerKeyIdentifier == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing WorkerKeyIdentifier")
	}
	if w.WorkerId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing WorkerId")
	}
	if w.WorkerSigningPubKey == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing WorkerSigningPubKey")
	}
	if w.WorkerEncryptionPubKey == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing WorkerEncryptionPubKey")
	}
	if w.CtControllerEncryptionPrivKey == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing encrypted ControllerEncryptionPrivKey")
	}
	if w.KeyId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing KeyId")
	}
	if w.Nonce == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing Nonce")
	}

	return nil
}

// TableName returns the table name.
func (w *WorkerAuth) TableName() string {
	if w.tableName != "" {
		return w.tableName
	}
	return "worker_auth_authorized"
}

// SetTableName sets the table name.
func (w *WorkerAuth) SetTableName(n string) {
	w.tableName = n
}

// WorkerCertBundle contains all fields related to a WorkerCertBundle resource
// This includes the serial number of the issuing CA, the worker id, and the certificate bundles issued by the CA
type WorkerCertBundle struct {
	*store.WorkerCertBundle
	tableName string `gorm:"-"`
}

func newWorkerCertBundle(ctx context.Context, certificatePublicKey []byte, workerKeyIdentifier string, certBundle []byte) (*WorkerCertBundle, error) {
	const op = "server.newWorkerCertBundle"

	if certificatePublicKey == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no certificatePublicKey")
	}
	if workerKeyIdentifier == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no workerKeyIdentifier")
	}
	if certBundle == nil || len(certBundle) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty certBundle")
	}

	l := &WorkerCertBundle{
		WorkerCertBundle: &store.WorkerCertBundle{
			RootCertificatePublicKey: certificatePublicKey,
			WorkerKeyIdentifier:      workerKeyIdentifier,
			CertBundle:               certBundle,
		},
	}
	return l, nil
}

func allocWorkerCertBundle() *WorkerCertBundle {
	return &WorkerCertBundle{
		WorkerCertBundle: &store.WorkerCertBundle{},
	}
}

func (w *WorkerCertBundle) clone() *WorkerCertBundle {
	cp := proto.Clone(w.WorkerCertBundle)
	return &WorkerCertBundle{
		WorkerCertBundle: cp.(*store.WorkerCertBundle),
	}
}

// Validate is called before storing a WorkerCertBundle in the db
func (w *WorkerCertBundle) ValidateNewWorkerCertBundle(ctx context.Context) error {
	const op = "server.(WorkerCertBundle).validateNewWorkerCertBundle"
	if w.RootCertificatePublicKey == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing CertificatePublicKey")
	}
	if w.WorkerKeyIdentifier == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing WorkerKeyIdentifier")
	}
	if w.CertBundle == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing certificate bundle")
	}

	return nil
}

// TableName returns the table name.
func (w *WorkerCertBundle) TableName() string {
	if w.tableName != "" {
		return w.tableName
	}
	return "worker_auth_certificate_bundle"
}

// SetTableName sets the table name.
func (w *WorkerCertBundle) SetTableName(n string) {
	w.tableName = n
}
