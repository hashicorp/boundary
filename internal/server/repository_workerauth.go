// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"crypto/x509"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/fatih/structs"
	"github.com/hashicorp/boundary/internal/daemon/cluster"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Ensure we implement the Storage interfaces
var (
	_ nodeenrollment.NodeIdLoader = (*WorkerAuthRepositoryStorage)(nil)
)

type rootCertificatesVersion struct {
	Version uint32 `mapstructure:"version"`
}

// WorkerAuthRepositoryStorage is the Worker Auth database repository
type WorkerAuthRepositoryStorage struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
}

// NewRepositoryStorage creates a new WorkerAuthRepositoryStorage that implements the Storage interface
func NewRepositoryStorage(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms) (*WorkerAuthRepositoryStorage, error) {
	const op = "server.(WorkerAuthRepositoryStorage).NewRepositoryStorage"
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
func (r *WorkerAuthRepositoryStorage) Store(ctx context.Context, msg nodeenrollment.MessageWithId) error {
	const op = "server.(WorkerAuthRepositoryStorage).Store"
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

		if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(read db.Reader, w db.Writer) error {
			return StoreNodeInformationTx(ctx, read, w, r.kms, scope.Global.String(), t)
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
func StoreNodeInformationTx(ctx context.Context, reader db.Reader, writer db.Writer, kmsCache *kms.Kms, scopeId string, node *types.NodeInformation, _ ...Option) error {
	const op = "server.(WorkerAuthRepositoryStorage).StoreNodeInformationTx"
	switch {
	case isNil(reader):
		return errors.New(ctx, errors.InvalidParameter, op, "missing reader")
	case isNil(writer):
		return errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	case isNil(kmsCache):
		return errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	case scopeId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	case node == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing NodeInformation")
	}

	databaseWrapper, err := kmsCache.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	var workerId string
	if node.WrappingRegistrationFlowInfo != nil {
		if util.IsNil(node.WrappingRegistrationFlowInfo.ApplicationSpecificParams) {
			return errors.New(ctx, errors.InvalidParameter, op, "in wrapping registration flow but application specific parameters not provided")
		}
		// In this case we are using the wrapping registration flow and it's
		// been validated; we need to upsert first to ensure that the worker
		// exists in the database.
		wci := new(cluster.WorkerConnectionInfo)
		if err := mapstructure.Decode(node.WrappingRegistrationFlowInfo.ApplicationSpecificParams.AsMap(), wci); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if wci.Name == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "in wrapping registration flow but worker name not provided")
		}
		if wci.BoundaryVersion == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "in wrapping registration flow but boundary version not provided")
		}
		wConf := NewWorker(scopeId,
			WithName(wci.Name),
			WithDescription(wci.Description),
			WithReleaseVersion(fmt.Sprintf("Boundary v%s", wci.BoundaryVersion)),
		)
		wConf.Type = PkiWorkerType.String()
		wConf.PublicId, err = NewWorkerIdFromScopeAndName(ctx, scopeId, wci.Name)
		if err != nil || wConf.PublicId == "" {
			return errors.Wrap(ctx, err, op, errors.WithMsg("error creating a worker id"))
		}
		workerCreateConflict := &db.OnConflict{
			Target: db.Columns{"public_id"},
			Action: db.SetColumns([]string{"release_version", "name", "description"}),
		}

		// Before going ahead with this, we need to see if this is an upgrade
		// case from the old KMS auth method. If so we need to delete first as
		// type is immutable.
		lookupWorker := allocWorker()
		lookupWorker.PublicId = wConf.PublicId
		err := reader.LookupById(ctx, &lookupWorker)
		switch {
		case err == nil:
			if lookupWorker.Type == KmsWorkerType.String() {
				// Delete it
				rowsDeleted, err := writer.Delete(ctx, lookupWorker)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("error deleting kms typed worker with matching id"))
				}
				if rowsDeleted != 1 {
					return errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("deleted %d rows, expected to delete 1", rowsDeleted))
				}
			}
		case errors.Convert(err) != nil && errors.Convert(err).Code == errors.RecordNotFound:
			// all good
		default:
			return errors.Wrap(ctx, err, op)
		}

		var withRowsAffected int64
		err = writer.Create(
			ctx,
			wConf,
			db.WithOnConflict(workerCreateConflict),
			db.WithReturnRowsAffected(&withRowsAffected),
		)
		switch {
		case err != nil:
			return errors.Wrap(ctx, err, op, errors.WithMsg("error creating a worker"))
		case withRowsAffected == 0:
			return errors.New(ctx, errors.NotUnique, op, "error updating worker")
		}
		workerId = wConf.PublicId
	}

	nodeAuth := allocWorkerAuth()
	nodeAuth.WorkerKeyIdentifier = node.Id
	nodeAuth.WorkerEncryptionPubKey = node.EncryptionPublicKeyBytes
	nodeAuth.WorkerSigningPubKey = node.CertificatePublicKeyPkix
	nodeAuth.Nonce = node.RegistrationNonce
	nodeAuth.ControllerEncryptionPrivKey = node.ServerEncryptionPrivateKeyBytes

	if err := nodeAuth.encrypt(ctx, databaseWrapper); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if workerId == "" {
		// Get workerId from state passed in
		var result workerAuthWorkerId
		if err := mapstructure.Decode(node.State.AsMap(), &result); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		workerId = result.WorkerId
	}
	nodeAuth.WorkerId = workerId

	if err := nodeAuth.ValidateNewWorkerAuth(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Check if we already have a workerAuth record for this key id
	nodeAuthLookup := allocWorkerAuth()
	nodeAuthLookup.WorkerKeyIdentifier = node.Id
	if err := reader.LookupById(ctx, nodeAuthLookup); err != nil {
		switch {
		case errors.IsNotFoundError(err):
			// If we didn't find it, that's fine
		default:
			return errors.Wrap(ctx, err, op)
		}
	}

	// If the incoming workerAuth matches what we have stored, return a duplicate record error
	// This will cause nodeenrollment to lookup and return the already stored nodeInfo
	if nodeAuth.compare(nodeAuthLookup) {
		return new(types.DuplicateRecordError)
	}

	// It's possible a connection dropped during a rotate credentials response, so the control plane's stored
	// previous and current WorkerAuth records may not match what the worker has stored.
	// Check what the worker indicates is its previous key and fix what we have stored before inserting the new record.
	if node.PreviousCertificatePublicKeyPkix != nil {
		previousKeyId, err := nodeenrollment.KeyIdFromPkix(node.PreviousCertificatePublicKeyPkix)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		query := getWorkerAuthStateByKeyIdQuery
		rows, err := reader.Query(ctx, query, []any{sql.Named("worker_key_identifier", previousKeyId)})
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		defer rows.Close()

		var state string
		for rows.Next() {
			if err := reader.ScanRows(ctx, rows, &state); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
			}
		}
		if err := rows.Err(); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		// If it's previous... delete current, as it's incorrect and set this one to current to
		// ensure proper state rotation on store
		if state == previousWorkerAuthState {
			query := deleteWorkerAuthByKeyId
			_, err := writer.Exec(ctx, query, []any{sql.Named("worker_key_identifier", previousKeyId)})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			query = updateWorkerAuthStateByKeyId
			_, err = writer.Exec(ctx, query, []any{sql.Named("worker_key_identifier", previousKeyId)})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
	}

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
	const op = "server.(WorkerAuthRepositoryStorage).storeWorkerCertBundle"
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
	const op = "server.(WorkerAuthRepositoryStorage).convertRootCertificate"
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
	rootCert.IssuingCa = CaId
	rootCert.PrivateKey = cert.PrivateKeyPkcs8

	// Encrypt the private key
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if err = rootCert.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if err = rootCert.ValidateNewRootCertificate(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return rootCert, nil
}

func (r *WorkerAuthRepositoryStorage) storeRootCertificates(ctx context.Context, cert *types.RootCertificates) error {
	const op = "server.(WorkerAuthRepositoryStorage).storeRootCertificates"
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
			PrivateId: CaId,
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
func (r *WorkerAuthRepositoryStorage) Load(ctx context.Context, msg nodeenrollment.MessageWithId) error {
	const op = "server.(WorkerAuthRepositoryStorage).Load"
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

	case *types.ServerLedActivationToken:
		err = r.loadServerLedActivationToken(ctx, t)

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
// * the prior encryption key, if present
func (r *WorkerAuthRepositoryStorage) loadNodeInformation(ctx context.Context, node *types.NodeInformation) error {
	const op = "server.(WorkerAuthRepositoryStorage).loadNodeInformation"
	if node == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing NodeInformation")
	}

	query := getWorkerAuthsByWorkerKeyIdQuery
	rows, err := r.reader.Query(ctx, query, []any{sql.Named("worker_key_identifier", node.Id)})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	var workerAuths []*WorkerAuth
	for rows.Next() {
		var s WorkerAuth
		if err := r.reader.ScanRows(ctx, rows, &s); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
		}
		workerAuths = append(workerAuths, &s)
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	workerAuthorizedSet, err := r.validateWorkerAuths(ctx, workerAuths)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nodeenrollment.ErrNotFound
		}
		return errors.Wrap(ctx, err, op)
	}

	if workerAuthorizedSet == nil || workerAuthorizedSet.Current == nil {
		return nodeenrollment.ErrNotFound
	}

	var thisWorkerAuth *WorkerAuth
	switch {
	case node.Id == workerAuthorizedSet.Current.WorkerKeyIdentifier:
		thisWorkerAuth = workerAuthorizedSet.Current
		if workerAuthorizedSet.Previous != nil {
			priorKey := &types.EncryptionKey{
				KeyId:           workerAuthorizedSet.Previous.WorkerKeyIdentifier,
				PrivateKeyPkcs8: workerAuthorizedSet.Previous.ControllerEncryptionPrivKey,
				PrivateKeyType:  types.KEYTYPE_X25519,
				PublicKeyPkix:   workerAuthorizedSet.Previous.WorkerEncryptionPubKey,
				PublicKeyType:   types.KEYTYPE_X25519,
			}

			node.PreviousEncryptionKey = priorKey
		}
	case workerAuthorizedSet.Previous != nil && node.Id == workerAuthorizedSet.Previous.WorkerKeyIdentifier:
		thisWorkerAuth = workerAuthorizedSet.Previous
	default:
		// We shouldn't hit this based on the logic in validateWorkerAuths, but just in case...
		return errors.New(ctx, errors.NotSpecificIntegrity, op, "no worker auths match the passed worker key identifier")
	}

	node.EncryptionPublicKeyBytes = thisWorkerAuth.WorkerEncryptionPubKey
	node.CertificatePublicKeyPkix = thisWorkerAuth.WorkerSigningPubKey
	node.RegistrationNonce = thisWorkerAuth.Nonce

	// Default values are used for key types
	node.EncryptionPublicKeyType = types.KEYTYPE_X25519
	node.CertificatePublicKeyType = types.KEYTYPE_ED25519
	node.ServerEncryptionPrivateKeyType = types.KEYTYPE_X25519

	// Decrypt private key
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase, kms.WithKeyId(thisWorkerAuth.KeyId))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err = thisWorkerAuth.decrypt(ctx, databaseWrapper); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	node.ServerEncryptionPrivateKeyBytes = thisWorkerAuth.ControllerEncryptionPrivKey

	workerIdInfo := workerAuthWorkerId{WorkerId: thisWorkerAuth.GetWorkerId()}
	s := structs.New(workerIdInfo)
	s.TagName = "mapstructure"
	state, err := structpb.NewStruct(s.Map())
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	node.State = state

	// Get cert bundles from the other table
	certBundles, err := r.findCertBundles(ctx, node.Id)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	node.CertificateBundles = certBundles

	return nil
}

// Node information is loaded in two parts:
// * the workerAuth record
// * its certificate bundles
func (r *WorkerAuthRepositoryStorage) loadServerLedActivationToken(ctx context.Context, token *types.ServerLedActivationToken) error {
	const op = "server.(WorkerAuthRepositoryStorage).loadServerLedActivationToken"
	if token == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing ServerLedActivationToken")
	}

	activationTokenEntry := allocWorkerAuthServerLedActivationToken()

	err := r.reader.LookupWhere(ctx, activationTokenEntry, "token_id = ?", []any{token.Id})
	if err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nodeenrollment.ErrNotFound
		}
		return errors.Wrap(ctx, err, op)
	}

	token.State, err = AttachWorkerIdToState(ctx, activationTokenEntry.WorkerId)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Decrypt marshaled creation time
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase, kms.WithKeyId(activationTokenEntry.KeyId))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := activationTokenEntry.decrypt(ctx, databaseWrapper); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	token.CreationTimeMarshaled = activationTokenEntry.CreationTime

	token.CreationTime = new(timestamppb.Timestamp)
	if err := proto.Unmarshal(token.CreationTimeMarshaled, token.CreationTime); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

func (r *WorkerAuthRepositoryStorage) findCertBundles(ctx context.Context, workerKeyId string) ([]*types.CertificateBundle, error) {
	const op = "server.(WorkerAuthRepositoryStorage).findCertBundles"
	if workerKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty workerKeyId")
	}

	var bundles []*WorkerCertBundle
	err := r.reader.SearchWhere(ctx, &bundles, "worker_key_identifier = ?", []any{workerKeyId}, db.WithLimit(-1))
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

// FilterToAuthorizedWorkerKeyIds returns all the worker key identifiers that
// are authorizable from the slice of key identifiers provided to the function.
func (r *WorkerAuthRepositoryStorage) FilterToAuthorizedWorkerKeyIds(ctx context.Context, workerKeyIds []string) ([]string, error) {
	const op = "server.(WorkerAuthRepositoryStorage).FilterToAuthorizedWorkerKeyIds"
	if len(workerKeyIds) == 0 {
		return nil, nil
	}
	rows, err := r.reader.Query(ctx, authorizedWorkerQuery, []any{workerKeyIds})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	type rowsResult struct {
		WorkerKeyIdentifier string
	}
	var ret []string
	for rows.Next() {
		var result rowsResult
		err = r.reader.ScanRows(ctx, rows, &result)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		ret = append(ret, result.WorkerKeyIdentifier)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *WorkerAuthRepositoryStorage) loadRootCertificates(ctx context.Context, cert *types.RootCertificates) error {
	const op = "server.(WorkerAuthRepositoryStorage).loadRootCertificates"
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
		return nodeenrollment.ErrNotFound
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

		if err := r.reader.SearchWhere(ctx, &rootCertificate, "state = ?", []any{c}, db.WithLimit(-1)); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		if rootCertificate.Certificate == nil {
			return nodeenrollment.ErrNotFound
		}

		// decrypt private key
		databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase, kms.WithKeyId(rootCertificate.KeyId))
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err = rootCertificate.decrypt(ctx, databaseWrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		rootCert.CertificateDer = rootCertificate.Certificate
		rootCert.NotAfter = rootCertificate.NotValidAfter.Timestamp
		rootCert.NotBefore = rootCertificate.NotValidBefore.Timestamp
		rootCert.PublicKeyPkix = rootCertificate.PublicKey
		rootCert.PrivateKeyType = types.KEYTYPE_ED25519
		rootCert.PrivateKeyPkcs8 = rootCertificate.PrivateKey

		if c == string(NextState) {
			cert.Next = rootCert
		}
		if c == string(CurrentState) {
			cert.Current = rootCert
		}
	}

	return nil
}

// LoadByNodeId implements the NodeIdLoader storage interface
// LoadByNodeId loads values into the given message. The message must be populated
// with the Node ID value. If not found, the returned error should be ErrNotFound.
func (r *WorkerAuthRepositoryStorage) LoadByNodeId(ctx context.Context, msg nodeenrollment.MessageWithNodeId) error {
	const op = "server.(WorkerAuthRepositoryStorage).LoadByNodeId"
	if err := types.ValidateMessage(msg); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if msg.GetNodeId() == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "given message cannot be loaded as it has no node ID")
	}

	var err error
	switch t := msg.(type) {
	case *types.NodeInformationSet:
		err = r.loadNodeInfosByNodeId(ctx, t)
	default:
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("message type %T not supported for LoadByNodeId", t))
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

func (r *WorkerAuthRepositoryStorage) loadNodeInfosByNodeId(ctx context.Context, nodeInfos *types.NodeInformationSet) error {
	const op = "server.(WorkerAuthRepositoryStorage).loadNodeInfosByNodeId"
	if nodeInfos == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing NodeInformations")
	}

	query := getWorkerAuthsByWorkerIdQuery
	rows, err := r.reader.Query(ctx, query, []any{sql.Named("worker_id", nodeInfos.NodeId)})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	var workerAuths []*WorkerAuth
	for rows.Next() {
		var s WorkerAuth
		if err := r.reader.ScanRows(ctx, rows, &s); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
		}
		workerAuths = append(workerAuths, &s)
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if len(workerAuths) == 0 {
		return nodeenrollment.ErrNotFound
	}

	nodeInfos.Nodes = make([]*types.NodeInformation, 0, len(workerAuths))
	for _, workerAuth := range workerAuths {
		node := &types.NodeInformation{
			Id:                             workerAuth.WorkerKeyIdentifier,
			EncryptionPublicKeyBytes:       workerAuth.WorkerEncryptionPubKey,
			CertificatePublicKeyPkix:       workerAuth.WorkerSigningPubKey,
			RegistrationNonce:              workerAuth.Nonce,
			EncryptionPublicKeyType:        types.KEYTYPE_X25519,
			CertificatePublicKeyType:       types.KEYTYPE_ED25519,
			ServerEncryptionPrivateKeyType: types.KEYTYPE_X25519,
		}

		// Decrypt private key
		databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase, kms.WithKeyId(workerAuth.KeyId))
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err = workerAuth.decrypt(ctx, databaseWrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		node.ServerEncryptionPrivateKeyBytes = workerAuth.ControllerEncryptionPrivKey

		workerIdInfo := workerAuthWorkerId{WorkerId: workerAuth.GetWorkerId()}
		s := structs.New(workerIdInfo)
		s.TagName = "mapstructure"
		state, err := structpb.NewStruct(s.Map())
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		node.State = state

		// Get cert bundles from the other table
		certBundles, err := r.findCertBundles(ctx, workerAuth.WorkerKeyIdentifier)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		node.CertificateBundles = certBundles

		nodeInfos.Nodes = append(nodeInfos.Nodes, node)
	}

	return nil
}

// Remove implements the Storage interface.
// Remove removes the given message. Only the ID field of the message is considered.
func (r *WorkerAuthRepositoryStorage) Remove(ctx context.Context, msg nodeenrollment.MessageWithId) error {
	const op = "server.(WorkerAuthRepositoryStorage).Remove"
	if err := types.ValidateMessage(msg); err != nil {
		return errors.New(ctx, errors.InvalidParameter, op, "given message cannot be removed as it has no ID")
	}

	// Determine type of message to remove
	switch t := msg.(type) {
	case *types.NodeInformation:
		err := r.removeNodeInformation(ctx, t)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	case *types.ServerLedActivationToken:
		err := r.removeServerLedActivationToken(ctx, t)
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

func (r *WorkerAuthRepositoryStorage) removeNodeInformation(ctx context.Context, msg *types.NodeInformation) error {
	const op = "server.(WorkerAuthRepositoryStorage).removeNodeInformation"
	switch {
	case msg == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "nil node information")
	case msg.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "empty id")
	}

	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			_, err = w.Exec(ctx, deleteWorkerAuthQuery, []any{sql.Named("worker_key_identifier", msg.Id)})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			_, err = w.Exec(ctx, deleteWorkerCertBundlesQuery, []any{sql.Named("worker_key_identifier", msg.Id)})
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

func (r *WorkerAuthRepositoryStorage) removeServerLedActivationToken(ctx context.Context, msg *types.ServerLedActivationToken) error {
	const op = "server.(WorkerAuthRepositoryStorage).removeServerLedActivationToken"
	switch {
	case msg == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "nil node information")
	case msg.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "empty id")
	case msg.State == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing state")
	}

	var workerInfo workerAuthWorkerId
	if err := mapstructure.Decode(msg.State.AsMap(), &workerInfo); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if workerInfo.WorkerId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "state missing worker id")
	}

	actToken := allocWorkerAuthServerLedActivationToken()
	actToken.WorkerId = workerInfo.WorkerId
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rowsDeleted, err := w.Delete(ctx, actToken)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted != 1 {
				return errors.New(ctx, errors.UnexpectedRowsAffected, op, fmt.Sprintf("expected to delete one activation token, deleted %d", rowsDeleted))
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
	const op = "server.(WorkerAuthRepositoryStorage).removeCertificateAuthority"

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
			PrivateId: CaId,
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
	cert.State.Fields["version"] = structpb.NewNumberValue(float64(version + 1))

	return nil
}

func (r *WorkerAuthRepositoryStorage) removeRootCertificateWithWriter(ctx context.Context, id string, writer db.Writer) error {
	const op = "server.(WorkerAuthRepositoryStorage).removeRootCertificateWithWriter"
	if id == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "empty id")
	}
	if writer == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	}

	rows, err := writer.Exec(ctx, deleteRootCertificateQuery, []any{
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
	const op = "server.(WorkerAuthRepositoryStorage).List"

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
	const op = "server.(WorkerAuthRepositoryStorage).listNodeCertificates"

	var where string
	var nodeAuths []*WorkerAuth
	err := r.reader.SearchWhere(ctx, &nodeAuths, where, []any{}, db.WithLimit(-1))
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
	const op = "server.(WorkerAuthRepositoryStorage).listRootCertificates"

	var where string
	var rootCertificates []*RootCertificate
	err := r.reader.SearchWhere(ctx, &rootCertificates, where, []any{}, db.WithLimit(-1))
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
	const op = "server.(WorkerAuthRepositoryStorage).listCertificateAuthority"

	var where string
	var rootCertificates []*CertificateAuthority
	err := r.reader.SearchWhere(ctx, &rootCertificates, where, []any{}, db.WithLimit(-1))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var certIds []string
	for _, cert := range rootCertificates {
		certIds = append(certIds, cert.PrivateId)
	}

	return certIds, nil
}

func (r *WorkerAuthRepositoryStorage) validateWorkerAuths(ctx context.Context, workerAuths []*WorkerAuth) (*WorkerAuthSet, error) {
	const op = "server.(WorkerAuthRepositoryStorage).validateWorkerAuths"

	var previousWorkerAuth *WorkerAuth
	var currentWorkerAuth *WorkerAuth

	workerAuthsFound := len(workerAuths)
	switch {
	case workerAuthsFound == 0:
		return nil, errors.New(ctx, errors.RecordNotFound, op, "did not find worker auth records for worker", errors.WithoutEvent())
	case workerAuthsFound == 1:
		if workerAuths[0].State != currentWorkerAuthState {
			return nil, errors.New(ctx, errors.NotSpecificIntegrity, op,
				fmt.Sprintf("expected sole worker auth record to be in current state, found %s", workerAuths[0].State))
		} else {
			currentWorkerAuth = workerAuths[0]
		}
	case workerAuthsFound == 2:
		currentStateFound := false
		previousStateFound := false
		for _, w := range workerAuths {
			if w.State == currentWorkerAuthState {
				currentStateFound = true
				currentWorkerAuth = w
			} else if w.State == previousWorkerAuthState {
				previousStateFound = true
				previousWorkerAuth = w
			}
		}
		if !currentStateFound || !previousStateFound {
			return nil, errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("worker auth records in invalid set of states"))
		}
	default:
		return nil, errors.New(ctx, errors.NotSpecificIntegrity, op,
			fmt.Sprintf("expected 2 or fewer worker auth records, found %d", workerAuthsFound))
	}

	workerAuthSet := &WorkerAuthSet{
		Previous: previousWorkerAuth,
		Current:  currentWorkerAuth,
	}

	return workerAuthSet, nil
}

// FindWorkerAuthByWorkerId takes a workerId and returns the WorkerAuthSet for this worker.
func (r *WorkerAuthRepositoryStorage) FindWorkerAuthByWorkerId(ctx context.Context, workerId string) (*WorkerAuthSet, error) {
	const op = "server.(WorkerAuthRepositoryStorage).FindWorkerAuthByWorkerId"
	if len(workerId) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty worker ID")
	}

	var workerAuths []*WorkerAuth
	if err := r.reader.SearchWhere(ctx, &workerAuths, "worker_id = ?", []any{workerId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return r.validateWorkerAuths(ctx, workerAuths)
}
