package oidc

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"

	"github.com/hashicorp/cap/oidc"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

const (
	AttemptExpiration     = 2 * 60 * time.Second
	FinalRedirectEndpoint = "/authentication-complete" // TODO jimlambrt 2/2021 get redirect from FE before PR
	CallbackEndpoint      = "/callback"                // TODO jimlambrt 2/2021 get endpoint from Todd before PR
)

type (
	// OidcRepoFactory creates a new oidc repo
	OidcRepoFactory func() (*Repository, error)

	// IamRepoFactory creates a new iam repo
	IamRepoFactory func() (*iam.Repository, error)

	// AuthTokenRepFactory creates a new auth token repo
	AuthTokenRepFactory func() (*authtoken.Repository, error)
)

// StartAuth accepts a request to start an OIDC authentication/authorization
// attempt.  It returns two URLs.  authUrl is an OIDC authorization request URL.
// The authUrl includes a "state" parameter which is encrypted and has a payload
// which includes (among other things) the final redirect (calculated from the
// clientInfo), a token_request_id,  and nonce. The tokenUrl is the URL the
// client can use to retrieve the results of the user's OIDC authentication
// attempt. The tokenUrl contains a token_request_id, which is encrypted.
//
// Options supported:
//
// WithRoundTripPayload(string) provides an option for a client roundtrip
// payload.  This payload will be added to the final redirect as a query
// parameter.
func StartAuth(ctx context.Context, oidcRepoFn OidcRepoFactory, kms *kms.Kms, apiAddr string, authMethodId string, opt ...Option) (authUrl *url.URL, tokenUrl *url.URL, e error) {
	const op = "oidc.StartAuth"
	if apiAddr == "" {
		return nil, nil, errors.New(errors.InvalidParameter, op, "missing api address")
	}
	if kms == nil {
		return nil, nil, errors.New(errors.InvalidParameter, op, "missing kms")
	}
	if authMethodId == "" {
		return nil, nil, errors.New(errors.InvalidParameter, op, "missing auth method id")
	}
	r, err := oidcRepoFn()
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
	}
	am, err := r.lookupAuthMethod(ctx, authMethodId)
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
	}
	if am == nil {
		return nil, nil, errors.New(errors.RecordNotFound, op, fmt.Sprintf("auth method %s not found", authMethodId))
	}
	provider, err := convertToProvider(ctx, am)
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
	}
	callbackRedirect := fmt.Sprintf("%s/%s", apiAddr, CallbackEndpoint)

	opts := getOpts(opt...)
	finalRedirect := fmt.Sprintf("%s/%s", apiAddr, FinalRedirectEndpoint)
	if opts.withRoundtripPayload != "" {
		finalRedirect = fmt.Sprintf("%s?%s", finalRedirect, opts.withRoundtripPayload)
	}
	now := time.Now()
	createTime, err := ptypes.TimestampProto(now.Truncate(time.Second))
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "create timestamp failed", errors.WithWrap(err))
	}
	exp, err := ptypes.TimestampProto(now.Add(AttemptExpiration).Truncate(time.Second))
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "exp timestamp failed", errors.WithWrap(err))
	}
	tokenRequestId, err := authtoken.NewAuthTokenId()
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
	}
	nonce, err := oidc.NewID()
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "unable to generate nonce", errors.WithWrap(err))
	}
	hash, err := provider.ConfigHash()
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "unable to get provider config hash", errors.WithWrap(err))
	}
	st := &request.State{
		TokenRequestId:     tokenRequestId,
		CreateTime:         &timestamp.Timestamp{Timestamp: createTime},
		ExpirationTime:     &timestamp.Timestamp{Timestamp: exp},
		FinalRedirectUrl:   finalRedirect,
		Nonce:              nonce,
		ProviderConfigHash: hash,
	}

	stateWrapper, err := r.stateWrapper(ctx, am.ScopeId, authMethodId)
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
	}
	encodedEncryptedSt, err := encryptState(ctx, stateWrapper, am.ScopeId, authMethodId, st)
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
	}
	// a bare min oidc.Request needed for the provider.AuthURL(...) call.  We've intentionally not populated
	// things like Audiences, because this oidc.Request isn't cached and not intended for use in future legs
	// of the authen flow.
	oidcReq, err := oidc.NewRequest(
		AttemptExpiration,
		callbackRedirect,
		oidc.WithState(string(encodedEncryptedSt)),
		oidc.WithNonce(nonce))
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "unable to create oidc request", errors.WithWrap(err))
	}

	u, err := provider.AuthURL(ctx, oidcReq)
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "unable to get auth url from provider", errors.WithWrap(err))
	}
	authUrl, err = url.Parse(u)
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "unable to parse auth url", errors.WithWrap(err))
	}

	return authUrl, tokenUrl, nil
}

// Callback is an oidc domain service function for processing a successful OIDC
// Authentication Response from an IdP oidc callback. On success, it returns a
// final redirect URL for the response to the IdP.
//
// For more info on a successful OIDC Authentication Response see:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
//
// The service operation includes:
//
// * Decrypt the state which has been encrypted with the OIDC DEK. If decryption
// fails, and error is returned. Decrypted state payload includes the
// token_request_id, nonce and final_redirect_url.
//
// * Exchange the callbackCodeParameter for provider tokens and validate the
// tokens.  Call UserInfo endpoint using access token.
//
// * Use oidc.(Repository).upsertAccount to create/update account using ID
// Tokens claims. The "sub" claim as external ID and setting email and full name
// for the account.
//
// * Use iam.(Repository).LookupUserWithLogin(...) look up the iam.User matching
// the Account.
//
// * Use the authtoken.(Repository).CreateAuthToken(...) to create a pending
// auth token for the authenticated user.
func Callback(
	ctx context.Context,
	kms *kms.Kms,
	oidcRepoFn OidcRepoFactory,
	iamRepoFn IamRepoFactory,
	atRepoFn AuthTokenRepFactory,
	authMethodId, state, code string) (finalRedirect string, e error) {
	panic("to-do")
}

// TokenRequest is an oidc domain service function for processing a token
// request from a Boundary client.  Token requests are the result of a Boundary
// client polling the tokenUrl they received via StartAuth.  On success, it
// returns Boundary token.
//
// * Decrypt the tokenRequestId.  If encryption fails, it returns an error.
//
// * Use the authtoken.(Repository).IssueAuthToken to issue the request id's
// token and mark it as issued in the repo.  If the token is already issue, an
// error is returned.
func TokenRequest(ctx context.Context, kms *kms.Kms, atRepoFn AuthTokenRepFactory, tokenRequestId string) (string, error) {
	panic("to-do")
}

func encryptState(ctx context.Context, wrapper wrapping.Wrapper, scopeId, authMethodId string, reqState *request.State) (encodedEncryptedState string, e error) {
	const op = "oidc.encryptState"
	if wrapper == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing wrapper")
	}
	if scopeId == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing scope id")
	}
	if authMethodId == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing auth method id")
	}
	marshaled, err := proto.Marshal(reqState)
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithMsg("marshaling encrypted token"), errors.WithCode(errors.Encode))
	}
	blobInfo, err := wrapper.Encrypt(ctx, marshaled, nil)
	if err != nil {
		return "", errors.New(errors.Encrypt, op, "unable to encrypt request state", errors.WithWrap(err))
	}
	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithMsg("marshaling encrypted token"), errors.WithCode(errors.Encode))
	}
	encryptedSt := &request.EncryptedState{
		AuthMethodId: authMethodId,
		ScopeId:      scopeId,
		WrapperKeyId: wrapper.KeyID(),
		Ct:           marshaledBlob,
	}
	marshaledEncryptedSt, err := proto.Marshal(encryptedSt)
	if err != nil {
		return "", errors.New(errors.Unknown, op, "unable to marshal encrypted state", errors.WithWrap(err))
	}

	return base58.FastBase58Encoding(marshaledEncryptedSt), nil
}

func decryptState(ctx context.Context, wrapper wrapping.Wrapper, encodedEncryptedState string) (string, string, *request.State, error) {
	const op = "oidc.decryptState"
	if wrapper == nil {
		return "", "", nil, errors.New(errors.InvalidParameter, op, "missing wrapper")
	}
	if encodedEncryptedState == "" {
		return "", "", nil, errors.New(errors.InvalidParameter, op, "missing encoded/encrypted state")
	}
	decoded, err := base58.FastBase58Decoding(encodedEncryptedState)
	if err != nil {
		return "", "", nil, errors.New(errors.Unknown, op, "unable to decode state", errors.WithWrap(err))
	}
	var encryptedSt *request.EncryptedState
	if err := proto.Unmarshal(decoded, encryptedSt); err != nil {
		return "", "", nil, errors.New(errors.Unknown, op, "unable to marshal encoded/encrypted state", errors.WithWrap(err))
	}

	var blobInfo wrapping.EncryptedBlobInfo
	if err := proto.Unmarshal(encryptedSt.Ct, &blobInfo); err != nil {
		return "", "", nil, errors.New(errors.Unknown, op, "unable to marshal blob info", errors.WithWrap(err))
	}

	marshaledSt, err := wrapper.Decrypt(ctx, &blobInfo, nil)
	if err != nil {
		return "", "", nil, errors.New(errors.Encrypt, op, "unable to decrypt state", errors.WithWrap(err))
	}
	var st *request.State
	if err := proto.Unmarshal(marshaledSt, st); err != nil {
		return "", "", nil, errors.New(errors.Unknown, op, "unable to marshal request state", errors.WithWrap(err))
	}

	return encryptedSt.ScopeId, encryptedSt.AuthMethodId, st, nil
}
