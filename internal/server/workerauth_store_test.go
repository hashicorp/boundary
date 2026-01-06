// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRootCertStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kmsCache := kms.TestKms(t, conn, wrapper)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testKey, err := databaseWrapper.KeyId(ctx)
	require.NoError(t, err)

	beforeTimestamp := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(-1 * time.Hour))}
	afterTimestamp := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(1 * time.Hour))}
	publicKey := populateBytes(defaultLength)
	privateKey := populateBytes(defaultLength)
	certificate := populateBytes(defaultLength)

	type args struct {
		serialNumber   uint64
		certificate    []byte
		rootCertKeys   RootCertificateKeys
		notValidBefore *timestamp.Timestamp
		notValidAfter  *timestamp.Timestamp
		keyId          string
		state          CertificateState
	}

	tests := []struct {
		name             string
		args             args
		expectedRootCert *store.RootCertificate
		wantErr          bool
		wantCreateErr    bool
	}{
		{
			name: "rootcert-store-next",
			args: args{
				serialNumber:   1234567890,
				rootCertKeys:   RootCertificateKeys{publicKey: publicKey, privateKey: privateKey},
				certificate:    certificate,
				notValidBefore: beforeTimestamp,
				notValidAfter:  afterTimestamp,
				keyId:          testKey,
				state:          NextState,
			},
			expectedRootCert: &store.RootCertificate{
				SerialNumber:   1234567890,
				PublicKey:      publicKey,
				CtPrivateKey:   privateKey,
				Certificate:    certificate,
				NotValidBefore: beforeTimestamp,
				NotValidAfter:  afterTimestamp,
				KeyId:          testKey,
				State:          "next",
				IssuingCa:      CaId,
			},
			wantErr: false,
		},
		{
			name: "rootcert-store-current",
			args: args{
				serialNumber:   9876543210,
				rootCertKeys:   RootCertificateKeys{publicKey: publicKey, privateKey: privateKey},
				certificate:    certificate,
				notValidBefore: beforeTimestamp,
				notValidAfter:  afterTimestamp,
				keyId:          testKey,
				state:          CurrentState,
			},
			expectedRootCert: &store.RootCertificate{
				SerialNumber:   9876543210,
				PublicKey:      publicKey,
				CtPrivateKey:   privateKey,
				Certificate:    certificate,
				NotValidBefore: beforeTimestamp,
				NotValidAfter:  afterTimestamp,
				KeyId:          testKey,
				State:          "current",
				IssuingCa:      CaId,
			},
			wantErr: false,
		},
		{
			name: "rootcert-store-empty-key",
			args: args{
				serialNumber:   9876543210,
				rootCertKeys:   RootCertificateKeys{publicKey: populateBytes(0), privateKey: privateKey},
				certificate:    certificate,
				notValidBefore: beforeTimestamp,
				notValidAfter:  afterTimestamp,
				keyId:          testKey,
				state:          NextState,
			},
			wantErr: true,
		},
		{
			name: "rootcert-no-keys",
			args: args{
				serialNumber:   1011121314,
				certificate:    certificate,
				notValidBefore: beforeTimestamp,
				notValidAfter:  afterTimestamp,
				keyId:          testKey,
				state:          NextState,
			},
			wantErr: true,
		},
		{
			name: "rootcert-no-cert",
			args: args{
				serialNumber:   15161718,
				rootCertKeys:   RootCertificateKeys{publicKey: publicKey, privateKey: privateKey},
				notValidBefore: beforeTimestamp,
				notValidAfter:  afterTimestamp,
				keyId:          testKey,
				state:          NextState,
			},
			wantErr: true,
		},
		{
			name: "rootcert-invalid-timestamps",
			args: args{
				serialNumber:   1920212223,
				rootCertKeys:   RootCertificateKeys{publicKey: publicKey, privateKey: privateKey},
				certificate:    certificate,
				notValidBefore: afterTimestamp,
				notValidAfter:  beforeTimestamp,
				keyId:          testKey,
				state:          NextState,
			},
			wantCreateErr: true,
		},
		{
			name: "rootcert-invalid-timestamps-2",
			args: args{
				serialNumber:   2425262728,
				rootCertKeys:   RootCertificateKeys{publicKey: publicKey, privateKey: privateKey},
				certificate:    certificate,
				notValidBefore: afterTimestamp,
				notValidAfter:  afterTimestamp,
				keyId:          testKey,
				state:          NextState,
			},
			wantCreateErr: true,
		},
		{
			name: "rootcert-invalid-state",
			args: args{
				serialNumber:   3031323334,
				rootCertKeys:   RootCertificateKeys{publicKey: publicKey, privateKey: privateKey},
				certificate:    certificate,
				notValidBefore: beforeTimestamp,
				notValidAfter:  afterTimestamp,
				keyId:          testKey,
				state:          UnknownState,
			},
			wantErr: true,
		},
		{
			name: "rootcert-no-key-id",
			args: args{
				serialNumber:   4041424344,
				rootCertKeys:   RootCertificateKeys{publicKey: publicKey, privateKey: privateKey},
				certificate:    certificate,
				notValidBefore: beforeTimestamp,
				notValidAfter:  afterTimestamp,
				state:          NextState,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			cert, err := newRootCertificate(ctx, tt.args.serialNumber, tt.args.certificate, tt.args.notValidBefore, tt.args.notValidAfter,
				tt.args.rootCertKeys, tt.args.keyId, tt.args.state)

			if tt.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			require.NotNil(cert)

			err = rw.Create(ctx, cert)
			if tt.wantCreateErr {
				assert.Error(err)
				return
			} else {
				assert.NoError(err)
				assert.Equal(tt.expectedRootCert, cert.RootCertificate)
				assert.Empty(cmp.Diff(tt.expectedRootCert, cert, protocmp.Transform()))
			}

			deleted, err := rw.Exec(ctx, `delete from worker_auth_ca_certificate where state = ?`, []any{cert.State})
			assert.NoError(err)
			assert.Equal(1, deleted)
		})
	}
}

func TestDuplicateRootCert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kmsCache := kms.TestKms(t, conn, wrapper)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testKey, err := databaseWrapper.KeyId(ctx)
	require.NoError(t, err)

	beforeTimestamp := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(-1 * time.Hour))}
	afterTimestamp := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(1 * time.Hour))}

	// Attempt to create a duplicate CA and expect a failure
	certAuthority := newCertificateAuthority()
	err = rw.Create(ctx, certAuthority)
	require.Error(t, err)

	// Make two current and next root certs
	current1, err := newRootCertificate(ctx, rand.Uint64(), populateBytes(defaultLength), beforeTimestamp, afterTimestamp,
		RootCertificateKeys{publicKey: populateBytes(defaultLength), privateKey: populateBytes(defaultLength)},
		testKey, CurrentState)
	require.NoError(t, err)
	current2, err := newRootCertificate(ctx, rand.Uint64(), populateBytes(defaultLength), beforeTimestamp, afterTimestamp,
		RootCertificateKeys{publicKey: populateBytes(defaultLength), privateKey: populateBytes(defaultLength)},
		testKey, CurrentState)
	require.NoError(t, err)
	next1, err := newRootCertificate(ctx, rand.Uint64(), populateBytes(defaultLength), beforeTimestamp, afterTimestamp,
		RootCertificateKeys{publicKey: populateBytes(defaultLength), privateKey: populateBytes(defaultLength)},
		testKey, NextState)
	require.NoError(t, err)
	next2, err := newRootCertificate(ctx, rand.Uint64(), populateBytes(defaultLength), beforeTimestamp, afterTimestamp,
		RootCertificateKeys{publicKey: populateBytes(defaultLength), privateKey: populateBytes(defaultLength)},
		testKey, NextState)
	require.NoError(t, err)

	// Insert first set of certs
	err = rw.Create(ctx, current1)
	require.NoError(t, err)
	err = rw.Create(ctx, next1)
	require.NoError(t, err)

	// Insert second current cert and expect an error
	err = rw.Create(ctx, current2)
	require.Error(t, err)
	err = rw.Create(ctx, next2)
	require.Error(t, err)
}

func TestWorkerAuthStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kmsCache := kms.TestKms(t, conn, wrapper)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testKey, err := databaseWrapper.KeyId(ctx)
	require.NoError(t, err)

	worker := TestPkiWorker(t, conn, wrapper)

	wSignPubKey := populateBytes(defaultLength)
	wEncPubKey := populateBytes(defaultLength)
	workerKeys := WorkerKeys{workerSigningPubKey: wSignPubKey, workerEncryptionPubKey: wEncPubKey}
	controllerKey := populateBytes(defaultLength)
	nonce := populateBytes(defaultLength)

	type args struct {
		workerKeyIdentifier string
		workerId            string
	}
	tests := []struct {
		name               string
		args               args
		expectedWorkerAuth *store.WorkerAuth
		opt                []Option
		wantErr            bool
		wantCreateErr      bool
	}{
		{
			name: "workerauth-store",
			args: args{
				workerKeyIdentifier: "worker-auth-id-123",
				workerId:            worker.PublicId,
			},
			opt: []Option{
				WithWorkerKeys(workerKeys),
				WithControllerEncryptionPrivateKey(controllerKey),
				WithNonce(nonce),
				WithKeyId(testKey),
			},
			expectedWorkerAuth: &store.WorkerAuth{
				WorkerKeyIdentifier:         "worker-auth-id-123",
				WorkerId:                    worker.PublicId,
				WorkerSigningPubKey:         wSignPubKey,
				WorkerEncryptionPubKey:      wEncPubKey,
				ControllerEncryptionPrivKey: controllerKey,
				KeyId:                       testKey,
				Nonce:                       nonce,
			},
			wantErr: false,
		},
		{
			name: "workerauth-no-pkey",
			args: args{
				workerId: worker.PublicId,
			},
			opt: []Option{
				WithWorkerKeys(workerKeys),
				WithControllerEncryptionPrivateKey(controllerKey),
				WithNonce(nonce),
				WithKeyId(testKey),
			},
			wantErr: true,
		},
		{
			name: "workerauth-empty-pkey",
			args: args{
				workerKeyIdentifier: "",
				workerId:            worker.PublicId,
			},
			opt: []Option{
				WithWorkerKeys(workerKeys),
				WithControllerEncryptionPrivateKey(controllerKey),
				WithNonce(nonce),
				WithKeyId(testKey),
			},
			wantErr: true,
		},
		{
			name: "workerauth-invalid-workerid",
			args: args{
				workerKeyIdentifier: "worker-auth-id-101",
				workerId:            "bogus-worker",
			},
			opt: []Option{
				WithWorkerKeys(workerKeys),
				WithControllerEncryptionPrivateKey(controllerKey),
				WithNonce(nonce),
				WithKeyId(testKey),
			},
			wantCreateErr: true,
		},
		{
			name:    "empty-workerauth",
			args:    args{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			wAuth, err := newWorkerAuth(ctx, tt.args.workerKeyIdentifier, tt.args.workerId, tt.opt...)

			if tt.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			require.NotNil(wAuth)

			require.NoError(wAuth.encrypt(ctx, databaseWrapper))

			err = rw.Create(ctx, wAuth)
			if tt.wantCreateErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
				// Update and create time are automatically set
				tt.expectedWorkerAuth.CreateTime = wAuth.WorkerAuth.CreateTime
				tt.expectedWorkerAuth.UpdateTime = wAuth.WorkerAuth.UpdateTime
				require.NoError(wAuth.decrypt(ctx, databaseWrapper))
				// Remove ciphertext since that's not included in the expected
				wAuth.CtControllerEncryptionPrivKey = nil
				assert.Equal(tt.expectedWorkerAuth, wAuth.WorkerAuth)
				assert.Empty(cmp.Diff(tt.expectedWorkerAuth, wAuth, protocmp.Transform()))
			}
		})
	}
}

func TestWorkerCertBundle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKey, kmsWrapper := TestKmsKey(ctx, t, conn, wrapper)

	worker := TestPkiWorker(t, conn, wrapper)
	workerAuth := TestWorkerAuth(t, conn, worker, kmsWrapper)
	rootCA := TestRootCertificate(ctx, t, conn, testKey)
	certBundle := populateBytes(defaultLength)

	type args struct {
		certificatePubKey []byte
		workerAuthId      string
		certificateBundle []byte
	}
	tests := []struct {
		name          string
		args          args
		expected      *store.WorkerCertBundle
		wantErr       bool
		wantCreateErr bool
	}{
		{
			name: "workercertbundle-store",
			args: args{
				certificatePubKey: rootCA.PublicKey,
				workerAuthId:      workerAuth.WorkerKeyIdentifier,
				certificateBundle: certBundle,
			},
			expected: &store.WorkerCertBundle{
				RootCertificatePublicKey: rootCA.PublicKey,
				WorkerKeyIdentifier:      workerAuth.WorkerKeyIdentifier,
				CertBundle:               certBundle,
			},
			wantErr: false,
		},
		{
			name: "workercertbundle-empty-cert-bundle",
			args: args{
				certificatePubKey: rootCA.PublicKey,
				workerAuthId:      workerAuth.WorkerKeyIdentifier,
			},
			wantErr: true,
		},
		{
			name: "workercertbundle-no-worker-id",
			args: args{
				certificatePubKey: rootCA.PublicKey,
				certificateBundle: certBundle,
			},
			wantErr: true,
		},
		{
			name: "workercertbundle-invalid-worker-id",
			args: args{
				certificatePubKey: rootCA.PublicKey,
				workerAuthId:      "bogus-worker",
				certificateBundle: certBundle,
			},
			wantCreateErr: true,
		},
		{
			name: "workercertbundle-empty-publickey",
			args: args{
				workerAuthId:      workerAuth.WorkerKeyIdentifier,
				certificateBundle: certBundle,
			},
			wantErr: true,
		},
		{
			name: "workercertbundle-invalid-publickey",
			args: args{
				certificatePubKey: populateBytes(defaultLength),
				workerAuthId:      workerAuth.WorkerKeyIdentifier,
				certificateBundle: certBundle,
			},
			wantCreateErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			workerCertBundle, err := newWorkerCertBundle(ctx, tt.args.certificatePubKey, tt.args.workerAuthId, tt.args.certificateBundle)

			if tt.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			require.NotNil(workerCertBundle)

			err = rw.Create(ctx, workerCertBundle)
			if tt.wantCreateErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
				assert.Equal(tt.expected, workerCertBundle.WorkerCertBundle)
				assert.Empty(cmp.Diff(tt.expected, workerCertBundle, protocmp.Transform()))
			}
		})
	}
}
