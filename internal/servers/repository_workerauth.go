package servers

import (
	"context"
	"crypto/x509"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/fatih/structs"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/protobuf/proto"
)

// Ensure we implement the Storage interfaces
var (
	_ nodee.Storage = (*WorkerAuthRepositoryStorage)(nil)
)

type rootCertificatesVersion struct {
	Version uint32
}

// WorkerAuthRepositoryStorage is the Worker Auth database repository
type WorkerAuthRepositoryStorage struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
}

// NewRepositoryStorage creates a new WorkerAuthRepositoryStorage that implements the Storage interface
func NewRepositoryStorage(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms) (*WorkerAuthRepositoryStorage, error) {
	const op = "servers.(WorkerAuthRepositoryStorage).NewRepositoryStorage"
	switch {
	case isNil(r):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "reader is nil")
	case isNil(w):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case isNil(kms):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "kms is nil")
	}

	workerAuthRepoStorage := &WorkerAuthRepositoryStorage{
		reader: r,
		writer: w,
		kms:    kms,
	}

	return workerAuthRepoStorage, nil
}

// Store implements the Storage interface
func (r *WorkerAuthRepositoryStorage) Store(ctx context.Context, msg nodee.MessageWithId) error {
	const op = "servers.(WorkerAuthRepositoryStorage).Store"
	if err := types.ValidateMessage(msg); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if msg.GetId() == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "given message cannot be stored as it has no ID")
	}

	// Determine type of message to store
	switch t := msg.(type) {
	case *types.NodeInformation:
		// Encrypt the private key
		databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(read db.Reader, w db.Writer) error {
			return StoreNodeInformationTx(ctx, w, databaseWrapper, t)
		}); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	case *types.RootCertificates:
		err := r.storeRootCertificates(ctx, t)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	default:
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("message type %T not supported for Store", msg))
	}

	return nil
}

// StoreNodeInformationTx stores NodeInformation.  No options are currently
// supported.
//
// This function encapsulates all the work required within a dbw.TxHandler and
// allows this capability to be shared with other repositories or just called
// within a transaction.  To be clear, this repository function doesn't include
// its own transaction and is intended to be used within a transaction provided
// by the caller.
//
// Node information is stored in two parts:
// * the workerAuth record is stored with a reference to a worker
// * certificate bundles are stored with a reference to the workerAuth record and issuing root certificate
func StoreNodeInformationTx(ctx context.Context, writer db.Writer, databaseWrapper wrapping.Wrapper, node *types.NodeInformation, _ ...Option) error {
	const op = "servers.(WorkerAuthRepositoryStorage).storeNodeInformation"
	if isNil(writer) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	}
	if isNil(databaseWrapper) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing database wrapper")
	}
	if node == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing NodeInformation")
	}

	nodeAuth := allocWorkerAuth()
	nodeAuth.WorkerKeyIdentifier = node.Id
	nodeAuth.WorkerEncryptionPubKey = node.EncryptionPublicKeyBytes
	nodeAuth.WorkerSigningPubKey = node.CertificatePublicKeyPkix

	var err error
	nodeAuth.KeyId, err = databaseWrapper.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	nodeAuth.ControllerEncryptionPrivKey, err = encrypt(ctx, node.ServerEncryptionPrivateKeyBytes, databaseWrapper)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	nodeAuth.Nonce, err = encrypt(ctx, node.RegistrationNonce, databaseWrapper)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Get workerId from state passed in
	var result workerAuthWorkerId
	err = mapstructure.Decode(node.State.AsMap(), &result)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	nodeAuth.WorkerId = result.WorkerId

	if err := nodeAuth.ValidateNewWorkerAuth(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Store WorkerAuth
	if err := writer.Create(ctx, &nodeAuth); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	// Then store cert bundles associated with this WorkerAuth
	for _, c := range node.CertificateBundles {
		if err := storeWorkerCertBundle(ctx, c, nodeAuth.WorkerKeyIdentifier, writer); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}

	return nil
}

func storeWorkerCertBundle(
	ctx context.Context,
	bundle *types.CertificateBundle,
	workerKeyIdentifier string,
	writer db.Writer,
) error {
	const op = "servers.(WorkerAuthRepositoryStorage).storeWorkerCertBundle"
	if bundle == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing CertificateBundle")
	}
	if workerKeyIdentifier == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "empty workerKeyIdentifier")
	}
	if writer == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	}

	workerCertBundle := allocWorkerCertBundle()
	bundleBytes, err := proto.Marshal(bundle)
	if err != nil {
		return errors.New(ctx, errors.Encode, op, "error marshaling nodetypes.CertificateBundle", errors.WithWrap(err))
	}

	// Extract serial number from CA cert
	caCert := bundle.CaCertificateDer
	parsedCert, err := x509.ParseCertificate(caCert)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	workerCertBundle.RootCertificatePublicKey = parsedCert.AuthorityKeyId
	workerCertBundle.CertBundle = bundleBytes
	workerCertBundle.WorkerKeyIdentifier = workerKeyIdentifier

	err = workerCertBundle.ValidateNewWorkerCertBundle(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	err = writer.Create(ctx, &workerCertBundle)

	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *WorkerAuthRepositoryStorage) convertRootCertificate(ctx context.Context, cert *types.RootCertificate) (*RootCertificate, error) {
	const op = "servers.(WorkerAuthRepositoryStorage).convertRootCertificate"
	if cert == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing RootCertificate")
	}

	rootCert := allocRootCertificate()

	parsedCert, err := x509.ParseCertificate(cert.CertificateDer)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	rootCert.SerialNumber = parsedCert.SerialNumber.Uint64()
	rootCert.Certificate = cert.CertificateDer
	rootCert.NotValidAfter = timestamp.New(cert.NotAfter.AsTime())
	rootCert.NotValidBefore = timestamp.New(cert.NotBefore.AsTime())
	rootCert.PublicKey = cert.PublicKeyPkix
	rootCert.State = cert.Id
	rootCert.IssuingCa = ca_id

	// Encrypt the private key
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	rootCert.KeyId, err = databaseWrapper.KeyId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	rootCert.PrivateKey, err = encrypt(ctx, cert.PrivateKeyPkcs8, databaseWrapper)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	err = rootCert.ValidateNewRootCertificate(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return rootCert, nil
}

func (r *WorkerAuthRepositoryStorage) storeRootCertificates(ctx context.Context, cert *types.RootCertificates) error {
	const op = "servers.(WorkerAuthRepositoryStorage).storeRootCertificates"
	if cert == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing RootCertificate")
	}

	nextCert, err := r.convertRootCertificate(ctx, cert.Next)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert next root certificate"))
	}
	currentCert, err := r.convertRootCertificate(ctx, cert.Current)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert current root certificate"))
	}
	// Use passed version
	var result rootCertificatesVersion
	err = mapstructure.Decode(cert.State.AsMap(), &result)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	version := uint32(1)
	if result.Version != 0 {
		version = result.Version
	}
	certAuthority := &CertificateAuthority{
		CertificateAuthority: &store.CertificateAuthority{
			PrivateId: ca_id,
			Version:   version + 1,
		},
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			// Delete the old certs
			if err = r.removeRootCertificateWithWriter(ctx, string(CurrentState), w); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if err = r.removeRootCertificateWithWriter(ctx, string(NextState), w); err != nil {
				return errors.Wrap(ctx, err, op)
			}

			// Update the certAuthority's version column
			rowsUpdated, err := w.Update(ctx, certAuthority, []string{"Version"}, nil, db.WithVersion(&version))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated CertificateAuthority and %d rows updated", rowsUpdated))
			}

			// Then insert the new certs
			if nextCert != nil {
				if err = w.Create(ctx, &nextCert); err != nil {
					return errors.Wrap(ctx, err, op)
				}
			}
			if currentCert != nil {
				if err = w.Create(ctx, &currentCert); err != nil {
					return errors.Wrap(ctx, err, op)
				}
			}
			return nil
		},
	)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

// Load implements the Storage interface.
// Load loads values into the given message. The message must be populated
// with the ID value. If not found, the returned error should be ErrNotFound.
func (r *WorkerAuthRepositoryStorage) Load(ctx context.Context, msg nodee.MessageWithId) error {
	const op = "servers.(WorkerAuthRepositoryStorage).Load"
	if err := types.ValidateMessage(msg); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if msg.GetId() == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "given message cannot be loaded as it has no ID")
	}

	var err error
	switch t := msg.(type) {
	case *types.NodeInformation:
		err = r.loadNodeInformation(ctx, t)

	case *types.RootCertificates:
		err = r.loadRootCertificates(ctx, t)

	default:
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("message type %T not supported for Load", t))
	}

	if err != nil {
		if err == nodeenrollment.ErrNotFound {
			// Don't wrap as this will confuse things
			return err
		}
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

// Node information is loaded in two parts:
// * the workerAuth record
// * its certificate bundles
func (r *WorkerAuthRepositoryStorage) loadNodeInformation(ctx context.Context, node *types.NodeInformation) error {
	const op = "servers.(WorkerAuthRepositoryStorage).loadNodeInformation"
	if node == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing NodeInformation")
	}

	authorizedWorker, err := r.findWorkerAuth(ctx, node)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if authorizedWorker == nil {
		return nodee.ErrNotFound
	}

	node.EncryptionPublicKeyBytes = authorizedWorker.WorkerEncryptionPubKey
	node.CertificatePublicKeyPkix = authorizedWorker.WorkerSigningPubKey

	// Default values are used for key types
	node.EncryptionPublicKeyType = types.KEYTYPE_X25519
	node.CertificatePublicKeyType = types.KEYTYPE_ED25519
	node.ServerEncryptionPrivateKeyType = types.KEYTYPE_X25519

	// Decrypt private key
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase, kms.WithKeyId(authorizedWorker.KeyId))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	node.ServerEncryptionPrivateKeyBytes, err = decrypt(ctx, authorizedWorker.ControllerEncryptionPrivKey, databaseWrapper)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	node.RegistrationNonce, err = decrypt(ctx, authorizedWorker.Nonce, databaseWrapper)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Get cert bundles from the other table
	certBundles, err := r.findCertBundles(ctx, node.Id)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	node.CertificateBundles = certBundles

	return nil
}

func (r *WorkerAuthRepositoryStorage) findCertBundles(ctx context.Context, workerKeyId string) ([]*types.CertificateBundle, error) {
	const op = "servers.(WorkerAuthRepositoryStorage).findCertBundles"
	if workerKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty workerKeyId")
	}

	var bundles []*WorkerCertBundle
	err := r.reader.SearchWhere(ctx, &bundles, "worker_key_identifier = ?", []interface{}{workerKeyId}, db.WithLimit(-1))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	certBundle := []*types.CertificateBundle{}
	for _, bundle := range bundles {
		thisBundle := &types.CertificateBundle{}
		if err := proto.Unmarshal(bundle.WorkerCertBundle.CertBundle, thisBundle); err != nil {
			return nil, errors.New(ctx, errors.Decode, op, "error unmarshaling message", errors.WithWrap(err))
		}
		certBundle = append(certBundle, thisBundle)
	}

	return certBundle, nil
}

func (r *WorkerAuthRepositoryStorage) findWorkerAuth(ctx context.Context, node *types.NodeInformation) (*WorkerAuth, error) {
	const op = "servers.(WorkerAuthRepositoryStorage).findWorkerAuth"
	if node == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "node is nil")
	}

	worker := allocWorkerAuth()
	worker.WorkerKeyIdentifier = node.Id

	err := r.reader.LookupById(ctx, worker)
	if err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}

	return worker, nil
}

func (r *WorkerAuthRepositoryStorage) loadRootCertificates(ctx context.Context, cert *types.RootCertificates) error {
	const op = "servers.(WorkerAuthRepositoryStorage).loadRootCertificates"
	if cert == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "cert is nil")
	}

	// See if we have the CertificateAuthority first
	certAuthority := &CertificateAuthority{
		CertificateAuthority: &store.CertificateAuthority{
			PrivateId: cert.Id,
		},
	}
	err := r.reader.LookupById(ctx, certAuthority)
	if err != nil {
		return nodee.ErrNotFound
	}

	// Add version to state field of cert
	versionMap := &rootCertificatesVersion{Version: certAuthority.Version}
	stateOpt := structs.Map(versionMap)
	state, err := structpb.NewStruct(stateOpt)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	cert.State = state

	// Load current and next certificates
	certsToFind := []string{string(NextState), string(CurrentState)}
	for _, c := range certsToFind {

		rootCertificate := allocRootCertificate()
		rootCert := &types.RootCertificate{}

		if err := r.reader.SearchWhere(ctx, &rootCertificate, "state = ?", []interface{}{c}, db.WithLimit(-1)); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		if rootCertificate.Certificate == nil {
			return nodee.ErrNotFound
		}

		rootCert.CertificateDer = rootCertificate.Certificate
		rootCert.NotAfter = rootCertificate.NotValidAfter.Timestamp
		rootCert.NotBefore = rootCertificate.NotValidBefore.Timestamp
		rootCert.PublicKeyPkix = rootCertificate.PublicKey
		rootCert.PrivateKeyType = types.KEYTYPE_ED25519

		// decrypt private key
		databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase, kms.WithKeyId(rootCertificate.KeyId))
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		rootCert.PrivateKeyPkcs8, err = decrypt(ctx, rootCertificate.PrivateKey, databaseWrapper)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}

		if c == string(NextState) {
			cert.Next = rootCert
		}
		if c == string(CurrentState) {
			cert.Current = rootCert
		}
	}

	return nil
}

// Remove implements the Storage interface.
// Remove removes the given message. Only the ID field of the message is considered.
func (r *WorkerAuthRepositoryStorage) Remove(ctx context.Context, msg nodee.MessageWithId) error {
	const op = "servers.(WorkerAuthRepositoryStorage).Remove"
	if err := types.ValidateMessage(msg); err != nil {
		return errors.New(ctx, errors.InvalidParameter, op, "given message cannot be removed as it has no ID")
	}

	// Determine type of message to remove
	switch msg.(type) {
	case *types.NodeInformation:
		err := r.removeNodeInformation(ctx, msg.GetId())
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	case *types.RootCertificates:
		err := r.removeCertificateAuthority(ctx, msg.(*types.RootCertificates))
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	default:
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("message type %T not supported for Remove", msg))
	}

	return nil
}

func (r *WorkerAuthRepositoryStorage) removeNodeInformation(ctx context.Context, id string) error {
	const op = "servers.(WorkerAuthRepositoryStorage).removeNodeInformation"
	if id == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "empty id")
	}

	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			_, err = w.Exec(ctx, deleteWorkerAuthQuery, []interface{}{sql.Named("worker_key_identifier", id)})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			_, err = w.Exec(ctx, deleteWorkerCertBundlesQuery, []interface{}{sql.Named("worker_key_identifier", id)})
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete workerAuth"))
			}
			return nil
		},
	)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

func (r *WorkerAuthRepositoryStorage) removeCertificateAuthority(ctx context.Context, cert *types.RootCertificates) error {
	const op = "servers.(WorkerAuthRepositoryStorage).removeCertificateAuthority"

	var result rootCertificatesVersion
	err := mapstructure.Decode(cert.State.AsMap(), &result)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	version := uint32(1)
	if result.Version != 0 {
		version = result.Version
	}
	certAuthority := &CertificateAuthority{
		CertificateAuthority: &store.CertificateAuthority{
			PrivateId: ca_id,
			Version:   version + 1,
		},
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			// Update the certAuthority's version column first
			rowsUpdated, err := w.Update(ctx, certAuthority, []string{"Version"}, nil, db.WithVersion(&version))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated CertificateAuthority and %d rows updated", rowsUpdated))
			}

			if err := r.removeRootCertificateWithWriter(ctx, string(CurrentState), w); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if err := r.removeRootCertificateWithWriter(ctx, string(NextState), w); err != nil {
				return errors.Wrap(ctx, err, op)
			}

			return nil
		},
	)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

func (r *WorkerAuthRepositoryStorage) removeRootCertificateWithWriter(ctx context.Context, id string, writer db.Writer) error {
	const op = "servers.(WorkerAuthRepositoryStorage).removeRootCertificateWithWriter"
	if id == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "empty id")
	}
	if writer == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	}

	rows, err := writer.Exec(ctx, deleteRootCertificateQuery, []interface{}{
		sql.Named("state", id),
	})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete root certificate"))
	}
	if rows > 1 {
		return errors.New(ctx, errors.MultipleRecords, op, "more than 1 root certificate would have been deleted")
	}
	return nil
}

// List implements the Storage interface.
// List returns a list of IDs; the type of the message is used to disambiguate what to list.
func (r *WorkerAuthRepositoryStorage) List(ctx context.Context, msg proto.Message) ([]string, error) {
	const op = "servers.(WorkerAuthRepositoryStorage).List"

	var err error
	var ids []string
	// Determine type of message to store
	switch msg.(type) {
	case *types.NodeInformation:
		ids, err = r.listNodeInformation(ctx)
	case *types.RootCertificate:
		ids, err = r.listRootCertificates(ctx)
	case *types.RootCertificates:
		ids, err = r.listCertificateAuthority(ctx)
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("message type %T not supported for List", msg))
	}
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ids, nil
}

// Returns a list of node auth IDs
func (r *WorkerAuthRepositoryStorage) listNodeInformation(ctx context.Context) ([]string, error) {
	const op = "servers.(WorkerAuthRepositoryStorage).listNodeCertificates"

	var where string
	var nodeAuths []*WorkerAuth
	err := r.reader.SearchWhere(ctx, &nodeAuths, where, []interface{}{}, db.WithLimit(-1))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var nodeIds []string
	for _, auth := range nodeAuths {
		nodeIds = append(nodeIds, auth.WorkerKeyIdentifier)
	}
	return nodeIds, nil
}

// Returns a list of root certificates
func (r *WorkerAuthRepositoryStorage) listRootCertificates(ctx context.Context) ([]string, error) {
	const op = "servers.(WorkerAuthRepositoryStorage).listRootCertificates"

	var where string
	var rootCertificates []*RootCertificate
	err := r.reader.SearchWhere(ctx, &rootCertificates, where, []interface{}{}, db.WithLimit(-1))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var certIds []string
	for _, cert := range rootCertificates {
		certIds = append(certIds, strconv.FormatUint(cert.SerialNumber, 10))
	}

	return certIds, nil
}

// Returns a list of certificate authorities
func (r *WorkerAuthRepositoryStorage) listCertificateAuthority(ctx context.Context) ([]string, error) {
	const op = "servers.(WorkerAuthRepositoryStorage).listCertificateAuthority"

	var where string
	var rootCertificates []*CertificateAuthority
	err := r.reader.SearchWhere(ctx, &rootCertificates, where, []interface{}{}, db.WithLimit(-1))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var certIds []string
	for _, cert := range rootCertificates {
		certIds = append(certIds, cert.PrivateId)
	}

	return certIds, nil
}

// encrypt value before writing it to the db
func encrypt(ctx context.Context, value []byte, wrapper wrapping.Wrapper) ([]byte, error) {
	const op = "servers.(WorkerAuthRepositoryStorage).encrypt"
	if value == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing value")
	}
	if wrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing wrapper")
	}

	blobInfo, err := wrapper.Encrypt(ctx, value)
	if err != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "error encrypting recovery info", errors.WithWrap(err))
	}
	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "error marshaling encrypted blob", errors.WithWrap(err))
	}
	return marshaledBlob, nil
}

func decrypt(ctx context.Context, value []byte, wrapper wrapping.Wrapper) ([]byte, error) {
	const op = "servers.(WorkerAuthRepositoryStorage).decrypt"
	if value == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing value")
	}
	if wrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing wrapper")
	}

	blobInfo := new(wrapping.BlobInfo)
	if err := proto.Unmarshal(value, blobInfo); err != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "error decoding encrypted blob", errors.WithWrap(err))
	}

	marshaledInfo, err := wrapper.Decrypt(ctx, blobInfo)
	if err != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "error decrypting recovery info", errors.WithWrap(err))
	}

	return marshaledInfo, nil
}
