package worker

import (
	"context"
	"errors"
	"time"

	berrors "github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/multihop"
	"github.com/hashicorp/nodeenrollment/types"
)

func (w *Worker) startAuthRotationTicking(cancelCtx context.Context) {
	const op = "worker.(Worker).startAuthRotationTicking"
	if w.conf.WorkerAuthKms != nil {
		// Nothing to do here, just immediately exit
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
			event.WriteSysEvent(cancelCtx, op, "auth rotation ticking shutting down")
			return

		case <-timer.C:
			resetDuration = defaultResetDuration

			// Check if it's time to rotate and if not don't do anything
			currentNodeCreds, err := types.LoadNodeCredentials(cancelCtx, w.WorkerAuthStorage, nodeenrollment.CurrentId, nodeenrollment.WithWrapper(w.conf.WorkerAuthStorageKms))
			if err != nil {
				if errors.Is(err, nodeenrollment.ErrNotFound) {
					// Be silent
					continue
				}
				event.WriteError(cancelCtx, op, err)
				continue
			}

			if currentNodeCreds == nil {
				event.WriteSysEvent(cancelCtx, op, "no error loading worker auth creds but nil creds, skipping rotation")
				continue
			}

			// Check the certificates to see if it's time
			if len(currentNodeCreds.CertificateBundles) != 2 {
				// Likely this means we haven't been authorized yet, and
				// unclear what to do in any other situation
				continue
			}

			var earliestValid, latestValid time.Time
			// Go through the bundles and find the full range of time that we
			// have valid certificates
			for _, bundle := range currentNodeCreds.CertificateBundles {
				if curr := bundle.CertificateNotBefore.AsTime(); earliestValid.IsZero() || curr.Before(earliestValid) {
					earliestValid = curr
				}
				if curr := bundle.CertificateNotAfter.AsTime(); latestValid.IsZero() || curr.After(latestValid) {
					latestValid = curr
				}
			}
			// Ensure that our time periods aren't somehow quite messed up
			now := time.Now()
			if earliestValid.After(now) || latestValid.Before(now) || earliestValid.After(latestValid) {
				// We basically have no valid creds so we can't rotate.
				// TODO (maybe): Have this trigger a new set of creds and request?
				event.WriteSysEvent(cancelCtx, op, "not within node creds validity period, unsure what to do, not rotating")
				continue
			}

			// Figure out the midpoint; if we're after it, try to rotate
			delta := latestValid.Sub(earliestValid)
			shouldRotate := now.Before(earliestValid.Add(delta / 2))
			if w.TestOverrideAuthRotationPeriod != 0 {
				shouldRotate = true
			}

			if !shouldRotate {
				continue
			}

			if err := rotateWorkerAuth(cancelCtx, w, currentNodeCreds); err != nil {
				event.WriteError(cancelCtx, op, err)
				continue
			}

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
	currentKeyId, err := nodeenrollment.KeyIdFromPkix(currentNodeCreds.CertificatePublicKeyPkix)
	if err != nil {
		return berrors.Wrap(ctx, err, op)
	}
	client := w.controllerMultihopConn.Load()
	if client == nil {
		return berrors.Wrap(ctx, err, op)
	}
	multihopClient, ok := client.(multihop.MultihopServiceClient)
	if !ok {
		return berrors.Wrap(ctx, err, op)
	}

	// Generate a new set of credentials but don't persist them yet
	newNodeCreds, err := types.NewNodeCredentials(
		ctx,
		w.WorkerAuthStorage,
		randReaderOpt,
		nodeenrollment.WithWrapper(w.conf.WorkerAuthKms),
		nodeenrollment.WithSkipStorage(true),
	)
	if err != nil {
		return berrors.Wrap(ctx, err, op)
	}

	// Get a signed request from the new credentials
	fetchReq, err := newNodeCreds.CreateFetchNodeCredentialsRequest(ctx, randReaderOpt)
	if err != nil {
		return berrors.Wrap(ctx, err, op)
	}

	// Encrypt the values to the server
	encFetchReq, err := nodeenrollment.EncryptMessage(ctx, currentKeyId, fetchReq, currentNodeCreds, randReaderOpt)
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
		currentKeyId,
		resp.EncryptedFetchNodeCredentialsResponse,
		currentNodeCreds,
		fetchResp,
	); err != nil {
		return berrors.Wrap(ctx, err, op)
	}

	// Call handle on the inner response, which will be encrypted to the
	// new node credentials. This will also store the result,
	// overwriting the current credentials.
	_, err = newNodeCreds.HandleFetchNodeCredentialsResponse(
		ctx,
		w.WorkerAuthStorage,
		fetchResp,
		nodeenrollment.WithWrapper(w.conf.WorkerAuthKms),
	)
	if err != nil {
		return berrors.Wrap(ctx, err, op)
	}

	return nil
}
