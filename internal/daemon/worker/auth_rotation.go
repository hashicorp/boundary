// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package worker

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	berrors "github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/multihop"
	"github.com/hashicorp/nodeenrollment/types"
)

func (w *Worker) startAuthRotationTicking(cancelCtx context.Context) {
	const op = "worker.(Worker).startAuthRotationTicking"

	if w.conf.RawConfig.Worker.UseDeprecatedKmsAuthMethod {
		event.WriteSysEvent(cancelCtx, op, "using deprecated kms worker authentication method; pki auth rotation ticking not running")
		return
	}

	// The default time to use when we encounter an error or some other reason
	// we can't get a better reset time
	const defaultResetDuration = time.Hour
	timer := time.NewTimer(defaultResetDuration)
	// You're not supposed to call reset on timers that haven't been stopped or
	// expired, so we stop it here so it resets in the loop below. That way if
	// we want to adjust time, e.g. for tests, we can set the resetDuration
	// value from within the loop
	timer.Stop()
	var resetDuration time.Duration // will start at 0, so we run immediately
	for {
		if w.TestOverrideAuthRotationPeriod != 0 {
			resetDuration = w.TestOverrideAuthRotationPeriod
		}
		timer.Reset(resetDuration)

		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(cancelCtx, op, "pki auth rotation ticking shutting down")
			return

		case <-timer.C:
			resetDuration = defaultResetDuration

			// Check if it's time to rotate and if not don't do anything
			currentNodeCreds, err := types.LoadNodeCredentials(
				cancelCtx,
				w.WorkerAuthStorage,
				nodeenrollment.CurrentId,
				nodeenrollment.WithStorageWrapper(w.conf.WorkerAuthStorageKms),
			)
			if err != nil {
				if errors.Is(err, nodeenrollment.ErrNotFound) {
					// Be silent
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
				resetDuration = 5 * time.Second
				continue
			}

			var earliestValid, latestValid time.Time
			// Go through the bundles and find the full range of time that we
			// have valid certificates
			var args []any
			for i, bundle := range currentNodeCreds.CertificateBundles {
				if curr := bundle.CertificateNotBefore.AsTime(); earliestValid.IsZero() || curr.Before(earliestValid) {
					earliestValid = curr
				}
				if curr := bundle.CertificateNotAfter.AsTime(); latestValid.IsZero() || curr.After(latestValid) {
					latestValid = curr
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
				args = append(args,
					fmt.Sprintf("leaf_cert_%d_id", i), certKeyId,
					fmt.Sprintf("leaf_cert_%d_not_before", i), cert.NotBefore.Format(time.RFC3339),
					fmt.Sprintf("leaf_cert_%d_not_after", i), cert.NotAfter.Format(time.RFC3339),
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
					fmt.Sprintf("ca_cert_%d_id", i), caCertKeyId,
					fmt.Sprintf("ca_cert_%d_not_before", i), caCert.NotBefore.Format(time.RFC3339),
					fmt.Sprintf("ca_cert_%d_not_after", i), caCert.NotAfter.Format(time.RFC3339),
				)
			}
			// Ensure that our time periods aren't somehow quite messed up
			now := time.Now()
			event.WriteSysEvent(cancelCtx, op, "checking if worker auth should rotate", append(
				args,
				"now", now.Format(time.RFC3339),
				"earliest_valid", earliestValid.Format(time.RFC3339),
				"latest_valid", latestValid.Format(time.RFC3339),
			)...,
			)
			if earliestValid.After(now) || latestValid.Before(now) || earliestValid.After(latestValid) {
				// We basically have no valid creds so we can't rotate.
				// TODO (maybe): Have this trigger a new set of creds and request?
				event.WriteSysEvent(cancelCtx, op, "not within worker creds validity period, unsure what to do, not rotating")
				continue
			}

			// Figure out the midpoint; if we're after it, try to rotate
			var shouldRotate bool
			delta := latestValid.Sub(earliestValid)
			switch {
			case w.TestOverrideAuthRotationPeriod != 0:
				shouldRotate = true
			default:
				resetDuration = latestValid.Sub(now) / 2
				shouldRotate = now.After(earliestValid.Add(delta / 2))
			}

			if !shouldRotate {
				event.WriteSysEvent(cancelCtx, op, "not time to rotate yet",
					"now", now.Format(time.RFC3339),
					"midpoint", earliestValid.Add(delta/2).Format(time.RFC3339),
					"next_check", now.Add(resetDuration).Format(time.RFC3339),
				)
				continue
			}

			if err := rotateWorkerAuth(cancelCtx, w, currentNodeCreds); err != nil {
				event.WriteError(cancelCtx, op, err)
				continue
			}
			event.WriteSysEvent(cancelCtx, op, "worker credentials rotated", "next_check", now.Add(resetDuration).Format(time.RFC3339))

			// TODO (maybe): Calculate new delta and set a custom retry time on the timer?
		}
	}
}

// rotateWorkerAuth is a one-stop shop to perform a rotation, given a valid set
// of current node credentials. Note that it doesn't really sanity check inputs;
// it is meant to be called from other functions that have validated these
// inputs and is separated out purely for (a) cleanliness/readability of the
// ticking function and (b) possible future re-use.
func rotateWorkerAuth(ctx context.Context, w *Worker, currentNodeCreds *types.NodeCredentials) error {
	const op = "worker.rotateWorkerAuth"

	randReaderOpt := nodeenrollment.WithRandomReader(w.conf.SecureRandomReader)

	// Ensure we can get some needed values prior to actually doing generation
	client := w.controllerMultihopConn.Load()
	if client == nil {
		return berrors.New(ctx, berrors.Internal, op, "nil multihop client")
	}
	multihopClient, ok := client.(multihop.MultihopServiceClient)
	if !ok {
		return berrors.New(ctx, berrors.Internal, op, "multihop client is not the right type")
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
		return berrors.Wrap(ctx, err, op)
	}

	err = newNodeCreds.SetPreviousEncryptionKey(currentNodeCreds)
	if err != nil {
		return berrors.Wrap(ctx, err, op)
	}

	// Get a signed request from the new credentials
	fetchReq, err := newNodeCreds.CreateFetchNodeCredentialsRequest(ctx, randReaderOpt)
	if err != nil {
		return berrors.Wrap(ctx, err, op)
	}

	// Encrypt the values to the server
	encFetchReq, err := nodeenrollment.EncryptMessage(ctx, fetchReq, currentNodeCreds, randReaderOpt)
	if err != nil {
		return berrors.Wrap(ctx, err, op)
	}

	resp, err := multihopClient.RotateNodeCredentials(ctx, &types.RotateNodeCredentialsRequest{
		CertificatePublicKeyPkix:             currentNodeCreds.CertificatePublicKeyPkix,
		EncryptedFetchNodeCredentialsRequest: encFetchReq,
	})
	if err != nil {
		return berrors.Wrap(ctx, err, op)
	}

	// Decrypt the response using current credentials
	fetchResp := new(types.FetchNodeCredentialsResponse)
	if err := nodeenrollment.DecryptMessage(
		ctx,
		resp.EncryptedFetchNodeCredentialsResponse,
		currentNodeCreds,
		fetchResp,
	); err != nil {
		return berrors.Wrap(ctx, err, op)
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
		return berrors.Wrap(ctx, err, op)
	}

	newKeyId, err := nodeenrollment.KeyIdFromPkix(newNodeCreds.CertificatePublicKeyPkix)
	if err != nil {
		return berrors.Wrap(ctx, err, op)
	}
	w.WorkerAuthCurrentKeyId.Store(newKeyId)

	var args []any
	for i, bundle := range newNodeCreds.GetCertificateBundles() {
		cert, err := x509.ParseCertificate(bundle.CertificateDer)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error parsing leaf certificate in new worker auth bundle: %w", err))
			continue
		}
		certPkixBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error marshaling leaf certificate public key in new worker auth bundle: %w", err))
			continue
		}
		certKeyId, err := nodeenrollment.KeyIdFromPkix(certPkixBytes)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error deriving pkix string from leaf certificate public key in new worker auth bundle: %w", err))
			continue
		}
		args = append(args,
			fmt.Sprintf("leaf_cert_%d_id", i), certKeyId,
			fmt.Sprintf("leaf_cert_%d_not_before", i), cert.NotBefore.Format(time.RFC3339),
			fmt.Sprintf("leaf_cert_%d_not_after", i), cert.NotAfter.Format(time.RFC3339),
		)
		caCert, err := x509.ParseCertificate(bundle.CaCertificateDer)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error parsing CA certificate in new worker auth bundle: %w", err))
			continue
		}
		caCertPkixBytes, err := x509.MarshalPKIXPublicKey(caCert.PublicKey)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error marshaling CA certificate public key in new worker auth bundle: %w", err))
			continue
		}
		caCertKeyId, err := nodeenrollment.KeyIdFromPkix(caCertPkixBytes)
		if err != nil {
			event.WriteError(ctx, op, fmt.Errorf("error deriving pkix string from CA certificate public key in new worker auth bundle: %w", err))
			continue
		}
		args = append(args,
			fmt.Sprintf("ca_cert_%d_id", i), caCertKeyId,
			fmt.Sprintf("ca_cert_%d_not_before", i), caCert.NotBefore.Format(time.RFC3339),
			fmt.Sprintf("ca_cert_%d_not_after", i), caCert.NotAfter.Format(time.RFC3339),
		)
	}
	event.WriteSysEvent(ctx, op, "rotate worker auth job finished successfully", args...)

	return nil
}
