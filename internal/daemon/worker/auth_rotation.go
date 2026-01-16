// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand"
	"time"

	berrors "github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/multihop"
	"github.com/hashicorp/nodeenrollment/types"
)

// The default time to use when we encounter an error or some other reason
// we can't get a better reset time
const defaultAuthRotationResetDuration = 5 * time.Second

func (w *Worker) startAuthRotationTicking(cancelCtx context.Context) {
	const op = "worker.(Worker).startAuthRotationTicking"

	event.WriteSysEvent(cancelCtx, op, "starting auth rotation ticking")

	// This will start at 0 which will cause us to run immediately
	var authRotationResetDuration time.Duration

	// Get a valid value in
	startNow := time.Now()
	w.AuthRotationNextRotation.Store(&startNow)

	timer := time.NewTimer(defaultAuthRotationResetDuration)
	lastRotation := time.Time{}.UTC()
	for {
		// Per the example in the docs, if you stop a timer you should drain the
		// channel if it returns false. However, their example of blindly
		// reading from the channel can deadlock. So we just do a select here to
		// be safer.
		timer.Stop()
		select {
		case <-timer.C:
		default:
		}

		if w.TestOverrideAuthRotationPeriod != 0 {
			authRotationResetDuration = w.TestOverrideAuthRotationPeriod
		}
		timer.Reset(authRotationResetDuration)

		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(cancelCtx, op, "pki auth rotation ticking shutting down")
			return

		case <-timer.C:
			// Add some jitter in case there is some issue to prevent thundering
			// herd
			jitter := time.Duration(rand.Intn(6)) * time.Second
			authRotationResetDuration = defaultAuthRotationResetDuration + jitter

			// Check if it's time to rotate and if not don't do anything
			currentNodeCreds, err := types.LoadNodeCredentials(
				cancelCtx,
				w.WorkerAuthStorage,
				nodeenrollment.CurrentId,
				nodeenrollment.WithStorageWrapper(w.conf.WorkerAuthStorageKms),
			)
			if err != nil {
				if errors.Is(err, nodeenrollment.ErrNotFound) {
					// Be silent as we likely haven't authorized yet
					continue
				}
				event.WriteError(cancelCtx, op, err)
				continue
			}

			if currentNodeCreds == nil {
				event.WriteSysEvent(cancelCtx, op, "no error loading worker pki auth creds but nil creds, skipping rotation")
				continue
			}

			// Check the certificates to see if it's time
			if len(currentNodeCreds.CertificateBundles) != 2 {
				// Likely this means we haven't been authorized yet, and unclear
				// what to do in any other situation. However, we should try
				// again fairly quickly because this may also be prior to the
				// first rotation and we want to ensure the validity period is
				// checked soon.
				continue
			}

			var current, next *types.CertificateBundle
			// Go through the bundles and intuit the rotation interval
			for _, bundle := range currentNodeCreds.CertificateBundles {
				if current == nil {
					current = bundle
					continue
				}
				if current.CertificateNotAfter.AsTime().Before(bundle.CertificateNotAfter.AsTime()) {
					next = bundle
				} else {
					next = current
					current = bundle
				}
			}
			rotationInterval := next.CertificateNotAfter.AsTime().Sub(current.CertificateNotAfter.AsTime())

			// This is useful output, but doesn't do anything other than output information
			str := "current"
			var args []any
			for i, bundle := range []*types.CertificateBundle{current, next} {
				if i == 1 {
					str = "next"
				}
				cert, err := x509.ParseCertificate(bundle.CertificateDer)
				if err != nil {
					event.WriteError(cancelCtx, op, fmt.Errorf("error parsing leaf certificate in current worker auth bundle: %w", err))
					continue
				}
				certPkixBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				if err != nil {
					event.WriteError(cancelCtx, op, fmt.Errorf("error marshaling leaf certificate public key in current worker auth bundle: %w", err))
					continue
				}
				certKeyId, err := nodeenrollment.KeyIdFromPkix(certPkixBytes)
				if err != nil {
					event.WriteError(cancelCtx, op, fmt.Errorf("error deriving pkix string from leaf certificate public key in current worker auth bundle: %w", err))
					continue
				}

				certId, err := nodeenrollment.KeyIdFromPkix(bundle.CertificateDer)
				if err != nil {
					event.WriteError(cancelCtx, op, fmt.Errorf("error deriving cert id from certificate in current worker auth bundle: %w", err))
					continue
				}
				args = append(args,
					fmt.Sprintf("leaf_cert_%s_cert_id", str), certId,
					fmt.Sprintf("leaf_cert_%s_key_id", str), certKeyId,
					fmt.Sprintf("leaf_cert_%s_not_before", str), cert.NotBefore.Format(time.RFC3339),
					fmt.Sprintf("leaf_cert_%s_not_after", str), cert.NotAfter.Format(time.RFC3339),
				)
				caCert, err := x509.ParseCertificate(bundle.CaCertificateDer)
				if err != nil {
					event.WriteError(cancelCtx, op, fmt.Errorf("error parsing CA certificate in current worker auth bundle: %w", err))
					continue
				}
				caCertPkixBytes, err := x509.MarshalPKIXPublicKey(caCert.PublicKey)
				if err != nil {
					event.WriteError(cancelCtx, op, fmt.Errorf("error marshaling CA certificate public key in current worker auth bundle: %w", err))
					continue
				}
				caCertKeyId, err := nodeenrollment.KeyIdFromPkix(caCertPkixBytes)
				if err != nil {
					event.WriteError(cancelCtx, op, fmt.Errorf("error deriving pkix string from CA certificate public key in current worker auth bundle: %w", err))
					continue
				}
				args = append(args,
					fmt.Sprintf("ca_cert_%s_key_id", str), caCertKeyId,
					fmt.Sprintf("ca_cert_%s_not_before", str), caCert.NotBefore.Format(time.RFC3339),
					fmt.Sprintf("ca_cert_%s_not_after", str), caCert.NotAfter.Format(time.RFC3339),
				)
			}

			// We'll rotate the first time we get this far, which is fine --
			// better to rotate early than late -- and then we'll rotate at
			// halfway through the current rotation interval
			now := time.Now().UTC()
			nextRotation := lastRotation.Add(rotationInterval / 2)
			if lastRotation.IsZero() {
				nextRotation = now
			}
			event.WriteSysEvent(cancelCtx, op, "checking if worker auth should rotate", append(
				args,
				"now", now.Format(time.RFC3339),
				"last_rotation", lastRotation.Format(time.RFC3339),
				"intuited_rotation_interval", rotationInterval.String(),
				"next_rotation", nextRotation.Format(time.RFC3339),
			)...,
			)

			// See if we don't need to do anything, and if so calculate reset
			// duration and loop back
			if !lastRotation.IsZero() && now.Before(nextRotation) {
				authRotationResetDuration = lastRotation.Add(rotationInterval / 2).Sub(now)
				continue
			}

			newRotationInterval, err := rotateWorkerAuth(cancelCtx, w, currentNodeCreds)
			if err != nil {
				event.WriteError(cancelCtx, op, err)
				continue
			}
			lastRotation = now
			nextRotation = lastRotation.Add(newRotationInterval / 2)
			w.AuthRotationNextRotation.Store(&nextRotation)
			authRotationResetDuration = nextRotation.Sub(now)
			event.WriteSysEvent(cancelCtx, op, "worker credentials rotated", "next_rotation", nextRotation)
		}
	}
}

// rotateWorkerAuth is a one-stop shop to perform a rotation, given a valid set
// of current node credentials. Note that it doesn't really sanity check inputs;
// it is meant to be called from other functions that have validated these
// inputs and is separated out purely for (a) cleanliness/readability of the
// ticking function and (b) possible future re-use.
func rotateWorkerAuth(ctx context.Context, w *Worker, currentNodeCreds *types.NodeCredentials) (time.Duration, error) {
	const op = "worker.rotateWorkerAuth"

	randReaderOpt := nodeenrollment.WithRandomReader(w.conf.SecureRandomReader)

	// Ensure we can get some needed values prior to actually doing generation
	client := w.controllerMultihopConn.Load()
	if client == nil {
		return 0, berrors.New(ctx, berrors.Internal, op, "nil multihop client")
	}
	multihopClient, ok := client.(multihop.MultihopServiceClient)
	if !ok {
		return 0, berrors.New(ctx, berrors.Internal, op, "multihop client is not the right type")
	}

	// Generate a new set of credentials but don't persist them yet
	newNodeCreds, err := types.NewNodeCredentials(
		ctx,
		w.WorkerAuthStorage,
		randReaderOpt,
		nodeenrollment.WithStorageWrapper(w.conf.WorkerAuthStorageKms),
		nodeenrollment.WithSkipStorage(true),
	)
	if err != nil {
		return 0, berrors.Wrap(ctx, err, op)
	}

	newNodeCreds.PreviousCertificatePublicKeyPkix = currentNodeCreds.CertificatePublicKeyPkix

	// Get a signed request from the new credentials
	fetchReq, err := newNodeCreds.CreateFetchNodeCredentialsRequest(ctx, randReaderOpt)
	if err != nil {
		return 0, berrors.Wrap(ctx, err, op)
	}

	// Encrypt the values to the server
	encFetchReq, err := nodeenrollment.EncryptMessage(ctx, fetchReq, currentNodeCreds, randReaderOpt)
	if err != nil {
		return 0, berrors.Wrap(ctx, err, op)
	}

	resp, err := multihopClient.RotateNodeCredentials(ctx, &types.RotateNodeCredentialsRequest{
		CertificatePublicKeyPkix:             currentNodeCreds.CertificatePublicKeyPkix,
		EncryptedFetchNodeCredentialsRequest: encFetchReq,
	})
	if err != nil {
		return 0, berrors.Wrap(ctx, err, op)
	}

	// Decrypt the response using current credentials
	fetchResp := new(types.FetchNodeCredentialsResponse)
	if err := nodeenrollment.DecryptMessage(
		ctx,
		resp.EncryptedFetchNodeCredentialsResponse,
		currentNodeCreds,
		fetchResp,
	); err != nil {
		return 0, berrors.Wrap(ctx, err, op)
	}

	// Call handle on the inner response, which will be encrypted to the
	// new node credentials. This will also store the result,
	// overwriting the current credentials.
	newNodeCreds, err = newNodeCreds.HandleFetchNodeCredentialsResponse(
		ctx,
		w.WorkerAuthStorage,
		fetchResp,
		nodeenrollment.WithStorageWrapper(w.conf.WorkerAuthStorageKms),
	)
	if err != nil {
		return 0, berrors.Wrap(ctx, err, op)
	}

	newKeyId, err := nodeenrollment.KeyIdFromPkix(newNodeCreds.CertificatePublicKeyPkix)
	if err != nil {
		return 0, berrors.Wrap(ctx, err, op)
	}
	w.WorkerAuthCurrentKeyId.Store(newKeyId)

	var current, next *types.CertificateBundle
	// Go through the bundles and intuit the rotation interval
	for _, bundle := range newNodeCreds.CertificateBundles {
		if current == nil {
			current = bundle
			continue
		}
		if current.CertificateNotAfter.AsTime().Before(bundle.CertificateNotAfter.AsTime()) {
			next = bundle
		} else {
			next = current
			current = bundle
		}
	}
	rotationInterval := next.CertificateNotAfter.AsTime().Sub(current.CertificateNotAfter.AsTime())

	// This is useful output, but doesn't do anything other than output information
	str := "current"
	var args []any
	for i, bundle := range []*types.CertificateBundle{current, next} {
		if i == 1 {
			str = "next"
		}
		cert, err := x509.ParseCertificate(bundle.CertificateDer)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error parsing leaf certificate in current worker auth bundle: %w", err))
			continue
		}
		certPkixBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error marshaling leaf certificate public key in current worker auth bundle: %w", err))
			continue
		}
		certKeyId, err := nodeenrollment.KeyIdFromPkix(certPkixBytes)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error deriving pkix string from leaf certificate public key in current worker auth bundle: %w", err))
			continue
		}
		certId, err := nodeenrollment.KeyIdFromPkix(bundle.CertificateDer)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error deriving cert id from certificate in current worker auth bundle: %w", err))
			continue
		}
		args = append(args,
			fmt.Sprintf("leaf_cert_%s_cert_id", str), certId,
			fmt.Sprintf("leaf_cert_%s_key_id", str), certKeyId,
			fmt.Sprintf("leaf_cert_%s_not_before", str), cert.NotBefore.Format(time.RFC3339),
			fmt.Sprintf("leaf_cert_%s_not_after", str), cert.NotAfter.Format(time.RFC3339),
		)
		caCert, err := x509.ParseCertificate(bundle.CaCertificateDer)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error parsing CA certificate in current worker auth bundle: %w", err))
			continue
		}
		caCertPkixBytes, err := x509.MarshalPKIXPublicKey(caCert.PublicKey)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error marshaling CA certificate public key in current worker auth bundle: %w", err))
			continue
		}
		caCertKeyId, err := nodeenrollment.KeyIdFromPkix(caCertPkixBytes)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error deriving pkix string from CA certificate public key in current worker auth bundle: %w", err))
			continue
		}
		args = append(args,
			fmt.Sprintf("ca_cert_%s_key_id", str), caCertKeyId,
			fmt.Sprintf("ca_cert_%s_not_before", str), caCert.NotBefore.Format(time.RFC3339),
			fmt.Sprintf("ca_cert_%s_not_after", str), caCert.NotAfter.Format(time.RFC3339),
		)
	}
	event.WriteSysEvent(ctx, op, "rotate worker auth job finished successfully", args...)

	return rotationInterval, nil
}
