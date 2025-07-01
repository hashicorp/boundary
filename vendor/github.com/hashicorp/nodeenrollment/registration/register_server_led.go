// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package registration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateServerLedActivationToken creates and stores a nonce and returns it;
// this nonce can be used when a node requests to fetch credentials to authorize
// it. The nonce is a serialized protobuf that also contains the creation time.
// The serialized value is HMAC'd before storage.
//
// The returned values are the activation token ID (used as the ID for storage)
// and the token itself.
//
// Supported options: WithRandomReader, WithStorageWrapper (passed through to
// NodeInformation.Store), WithSkipStorage, WithState (to encode state in the
// activation token)
func CreateServerLedActivationToken(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.ServerLedRegistrationRequest,
	opt ...nodeenrollment.Option,
) (string, string, error) {
	const op = "nodeenrollment.registration.RegisterViaServerLedFlow"

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return "", "", fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	switch {
	case req == nil:
		return "", "", fmt.Errorf("(%s) nil request", op)
	case !opts.WithSkipStorage && nodeenrollment.IsNil(storage):
		return "", "", fmt.Errorf("(%s) nil storage", op)
	}

	var (
		tokenEntry = new(types.ServerLedActivationToken)
		tokenNonce = new(types.ServerLedActivationTokenNonce)
	)

	// First create nonce values
	tokenNonce.Nonce = make([]byte, nodeenrollment.NonceSize)
	num, err := opts.WithRandomReader.Read(tokenNonce.Nonce)
	switch {
	case err != nil:
		return "", "", fmt.Errorf("(%s) error generating nonce: %w", op, err)
	case num != nodeenrollment.NonceSize:
		return "", "", fmt.Errorf("(%s) read incorrect number of bytes for nonce, wanted %d, got %d", op, nodeenrollment.NonceSize, num)
	}
	// Create a unique hmac key
	tokenNonce.HmacKeyBytes = make([]byte, 32)
	num, err = opts.WithRandomReader.Read(tokenNonce.HmacKeyBytes)
	switch {
	case err != nil:
		return "", "", fmt.Errorf("(%s) error generating hmac key bytes: %w", op, err)
	case num != 32:
		return "", "", fmt.Errorf("(%s) read incorrect number of bytes for hmac key, wanted %d, got %d", op, nodeenrollment.NonceSize, num)
	}

	// Now generate the returned value that will be transmitted by marshaling the token
	returnedTokenBytes, err := proto.Marshal(tokenNonce)
	if err != nil {
		return "", "", fmt.Errorf("(%s) error marshaling token nonce: %w", op, err)
	}

	tokenEntry.CreationTime = timestamppb.Now()
	tokenEntry.State = opts.WithState

	// Now, we're going to hmac the nonce; an encoding of the hmac value will
	// give us the ID for storage of the activation token entry. That way we
	// aren't storing usable values directly as entries in storage.
	hm := hmac.New(sha256.New, tokenNonce.HmacKeyBytes)
	idBytes := hm.Sum(tokenNonce.Nonce)
	tokenEntry.Id = base58.FastBase58Encoding(idBytes)

	if !opts.WithSkipStorage {
		// At this point everything is generated and both messages are prepared;
		// store the value
		if err := tokenEntry.Store(ctx, storage, opt...); err != nil {
			return "", "", fmt.Errorf("(%s) error storing activation token: %w", op, err)
		}
	}

	return tokenEntry.Id, fmt.Sprintf("%s%s", nodeenrollment.ServerLedActivationTokenPrefix, base58.FastBase58Encoding(returnedTokenBytes)), nil
}

// validateServerLedActivationToken validates that a token found in a fetch
// request is valid. It returns the authorized NodeInformation.
//
// Supported options: WithMaximumServerLedActivationTokenLifetime; other options
// are passed through to downstream functions.
func validateServerLedActivationToken(
	ctx context.Context,
	storage nodeenrollment.Storage,
	reqInfo *types.FetchNodeCredentialsInfo,
	tokenNonce *types.ServerLedActivationTokenNonce,
	opt ...nodeenrollment.Option,
) (*types.NodeInformation, error) {
	const op = "nodeenrollment.registration.FetchNodeCredentials"

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	case reqInfo == nil:
		return nil, fmt.Errorf("(%s) nil request info", op)
	case tokenNonce == nil:
		return nil, fmt.Errorf("(%s) nil token nonce", op)
	case len(tokenNonce.Nonce) == 0:
		return nil, fmt.Errorf("(%s) empty token nonce nonce", op)
	case len(tokenNonce.HmacKeyBytes) == 0:
		return nil, fmt.Errorf("(%s) empty token nonce hmac key bytes", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	// Generate the ID from the token values for lookup
	hm := hmac.New(sha256.New, tokenNonce.HmacKeyBytes)
	idBytes := hm.Sum(tokenNonce.Nonce)
	tokenEntry, err := types.LoadServerLedActivationToken(ctx, storage, base58.FastBase58Encoding(idBytes), opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error looking up activation token: %w", op, err)
	}
	if tokenEntry == nil {
		// Returning ErrNotFound here will result in the Fetch call returning unauthorized
		return nil, fmt.Errorf("(%s) activation token from lookup is nil: %w", op, nodeenrollment.ErrNotFound)
	}

	// Validate the time since creation
	switch {
	case tokenEntry.CreationTime == nil:
		return nil, fmt.Errorf("(%s) nil activation token creation time", op)
	case tokenEntry.CreationTime.AsTime().IsZero():
		return nil, fmt.Errorf("(%s) activation token creation time is zero", op)
	}
	if tokenEntry.CreationTime.AsTime().Add(opts.WithMaximumServerLedActivationTokenLifetime).Before(time.Now()) {
		return nil, fmt.Errorf("(%s) activation token has expired", op)
	}

	// If state was provided, use it. Note that it may clash if state is passed
	// into the function directly; either transfer state via token entry, or
	// when calling this function.
	if tokenEntry.State != nil {
		opt = append(opt, nodeenrollment.WithState(tokenEntry.State))
	}

	// We need to remove this since it's one-time-use. Note that it's up to the
	// storage implementation to have this be truly one-time or not (e.g. in a
	// transaction). If possible, storage should communicate anything unexpected
	// (such as the value not being found) as an error so we don't proceed
	// towards authorization.
	if err := storage.Remove(ctx, tokenEntry); err != nil {
		return nil, fmt.Errorf("(%s) error removing server-led activation token: %w", op, err)
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(reqInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	// Verify that we don't have an authorization already for the given key ID
	if keyCheck, _ := types.LoadNodeInformation(ctx, storage, keyId, opt...); keyCheck != nil {
		return nil, fmt.Errorf("(%s) node cannot be authorized as there is an existing node", op)
	}

	// Authorize the node; we'll then fall through to the rest of the fetch
	// workflow (we've already ensured we're not in an authorize call up
	// above)
	nodeInfo, err := authorizeNodeCommon(ctx, storage, reqInfo, opt...)
	return nodeInfo, err
}
