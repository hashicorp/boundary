package servers

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/servers/store"
	"google.golang.org/protobuf/proto"
)

// WorkerAuth contains all fields related to an authorized Worker resource
// This includes worker public keys, the controller encryption key,
// and certificate bundles issued by the Boundary CA
type WorkerAuth struct {
	*store.WorkerAuth
	tableName string `gorm:"-"`
}

// WorkerKeys contain the signing and encryption keys for a WorkerAuth resource
type WorkerKeys struct {
	workerSigningPubKey    []byte
	workerEncryptionPubKey []byte
}

func newWorkerAuth(ctx context.Context, workerKeyIdentifier, workerId string, opt ...Option) (*WorkerAuth, error) {
	const op = "servers.newWorkerAuth"
	opts := getOpts(opt...)

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

	if &opts.withWorkerKeys != nil {
		l.WorkerSigningPubKey = opts.withWorkerKeys.workerSigningPubKey
		l.WorkerEncryptionPubKey = opts.withWorkerKeys.workerEncryptionPubKey
	}
	if &opts.withControllerEncryptionPrivateKey != nil {
		l.ControllerEncryptionPrivKey = opts.withControllerEncryptionPrivateKey
	}
	if opts.withKeyId != "" {
		l.KeyId = opts.withKeyId
	}
	if opts.withNonce != nil {
		l.Nonce = opts.withNonce
	}
	return l, nil
}

func AllocWorkerAuth() *WorkerAuth {
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
	const op = "servers.(WorkerAuth).validateNewWorkerAuth"
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
	if w.ControllerEncryptionPrivKey == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing ControllerEncryptionPrivKey")
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
	const op = "servers.newWorkerCertBundle"

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
			CertificatePublicKey: certificatePublicKey,
			WorkerKeyIdentifier:  workerKeyIdentifier,
			CertBundle:           certBundle,
		},
	}
	return l, nil
}

func AllocWorkerCertBundle() *WorkerCertBundle {
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
	const op = "servers.(WorkerAuth).validateNewWorkerCertBundle"
	if w.CertificatePublicKey == nil {
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
