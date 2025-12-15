// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethods

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	oidcstore "github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/types/action"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"google.golang.org/grpc/codes"
)

const (
	// commands
	startCommand    = "start"
	callbackCommand = "callback"
	tokenCommand    = "token"

	// token request/response fields
	statusField = "status"

	// field names
	issuerField                            = "attributes.issuer"
	clientSecretField                      = "attributes.client_secret"
	clientIdField                          = "attributes.client_id"
	clientSecretHmacField                  = "attributes.client_secret_hmac"
	stateField                             = "attributes.state"
	callbackUrlField                       = "attributes.callback_url"
	apiUrlPrefixField                      = "attributes.api_url_prefix"
	idpCaCertsField                        = "attributes.idp_ca_certs"
	signingAlgorithmField                  = "attributes.signing_algorithms"
	disableDiscoveredConfigValidationField = "attributes.disable_discovered_config_validation"
	roundtripPayloadAttributesField        = "attributes.roundtrip_payload"
	codeField                              = "attributes.code"
	claimsScopesField                      = "attributes.claims_scopes"
	accountClaimMapsField                  = "attributes.account_claim_maps"
	promptsField                           = "attributes.prompts"
)

var oidcMaskManager handlers.MaskManager

func init() {
	var err error
	if oidcMaskManager, err = handlers.NewMaskManager(context.Background(), handlers.MaskDestination{&oidcstore.AuthMethod{}}, handlers.MaskSource{&pb.AuthMethod{}, &pb.OidcAuthMethodAttributes{}}); err != nil {
		panic(err)
	}

	IdActions[oidc.Subtype] = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
		action.ChangeState,
		action.Authenticate,
	)
}

type oidcState uint

const (
	_ oidcState = iota
	inactiveState
	privateState
	publicState
)

var oidcStateMap = map[string]oidcState{
	inactiveState.String(): inactiveState,
	privateState.String():  privateState,
	publicState.String():   publicState,
}

func (o oidcState) String() string {
	return [...]string{
		"unknown",
		"inactive",
		"active-private",
		"active-public",
	}[o]
}

// createOidcInRepo creates an oidc auth method in a repo and returns the result.
// This method should never return a nil AuthMethod without returning an error.
func (s Service) createOidcInRepo(ctx context.Context, scopeId string, item *pb.AuthMethod) (*oidc.AuthMethod, error) {
	u, _, _, err := toStorageOidcAuthMethod(ctx, scopeId, item)
	if err != nil {
		return nil, err
	}
	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateAuthMethod(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("unable to create auth method: %w", err)
	}
	return out, nil
}

func (s Service) updateOidcInRepo(ctx context.Context, scopeId string, req *pbs.UpdateAuthMethodRequest) (*oidc.AuthMethod, bool, error) {
	item := req.GetItem()
	u, dryRun, forced, err := toStorageOidcAuthMethod(ctx, scopeId, item)
	if err != nil {
		return nil, dryRun, err
	}
	u.PublicId = req.GetId()

	var opts []oidc.Option
	if forced {
		opts = append(opts, oidc.WithForce())
	}
	if dryRun {
		opts = append(opts, oidc.WithDryRun())
	}

	version := item.GetVersion()
	dbMask := oidcMaskManager.Translate(req.GetUpdateMask().GetPaths())
	if len(dbMask) == 0 {
		return nil, dryRun, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}

	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, dryRun, err
	}
	out, rowsUpdated, err := repo.UpdateAuthMethod(ctx, u, version, dbMask, opts...)
	if err != nil {
		return nil, dryRun, fmt.Errorf("unable to update auth method: %w", err)
	}
	if rowsUpdated == 0 && !dryRun && out == nil {
		return nil, dryRun, handlers.NotFoundErrorf("AuthMethod %q doesn't exist or incorrect version provided.", req.GetId())
	}
	return out, dryRun, nil
}

func (s Service) authenticateOidc(ctx context.Context, req *pbs.AuthenticateRequest, authResults *auth.VerifyResults) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).authenticateOidc"
	if req == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Nil request.")
	}
	if authResults == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Nil auth results.")
	}
	switch req.GetCommand() {
	case startCommand:
		return s.authenticateOidcStart(ctx, req)
	case callbackCommand:
		return s.authenticateOidcCallback(ctx, req)
	case tokenCommand:
		return s.authenticateOidcToken(ctx, req, authResults)
	}

	return &pbs.AuthenticateResponse{Command: req.GetCommand()}, nil
}

func (s Service) authenticateOidcStart(ctx context.Context, req *pbs.AuthenticateRequest) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).authenticateOidcStart"
	if req == nil {
		return nil, handlers.InvalidArgumentErrorf("Nil request.", nil)
	}

	var opts []oidc.Option
	attrs := req.GetOidcStartAttributes()
	if attrs.GetCachedRoundtripPayload() != "" {
		opts = append(opts, oidc.WithRoundtripPayload(attrs.GetCachedRoundtripPayload()))
	}

	authUrl, tokenId, err := oidc.StartAuth(ctx, s.oidcRepoFn, req.GetAuthMethodId(), opts...)
	switch {
	case errors.Match(errors.T(errors.AuthMethodInactive), err):
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.FailedPrecondition, "Cannot start authentication against an inactive OIDC auth method")
	case errors.Match(errors.T(errors.RecordNotFound), err):
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.NotFound, "Auth method %s was not found", req.GetAuthMethodId())
	case errors.Match(errors.T(errors.InvalidParameter), err):
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, err.Error())
	case err != nil:
		event.WriteError(ctx, op, err, event.WithInfoMsg("error starting the oidc authentication flow"))
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Error generating parameters for starting the OIDC flow. See the controller's log for more information.")
	}

	return &pbs.AuthenticateResponse{
		Command: req.GetCommand(),
		Attrs: &pbs.AuthenticateResponse_OidcAuthMethodAuthenticateStartResponse{
			OidcAuthMethodAuthenticateStartResponse: &pb.OidcAuthMethodAuthenticateStartResponse{
				AuthUrl: authUrl.String(),
				TokenId: tokenId,
			},
		},
	}, nil
}

// authenticateOidcCallback behaves differently than other service methods.
// Because of the way it this is called by the end user, it should only return
// an error if we are unable to lookup the auth method or the request
// parameters were invalid.  All other errors should be returned back through
// the response as a finalRedirectUrl to an endpoint that can properly show the
// error details.
func (s Service) authenticateOidcCallback(ctx context.Context, req *pbs.AuthenticateRequest) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).authenticateOidcCallback"
	// TODO: Return all errors (including the validate request based errors
	//   in the redirect URL once we start looking at the url used for this
	//   request instead of requiring the API URL to be set on the auth method.
	if req == nil {
		return nil, handlers.InvalidArgumentErrorf("Nil request.", nil)
	}

	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, err.Error())
	}
	am, err := repo.LookupAuthMethod(ctx, req.GetAuthMethodId())
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, err.Error())
	}
	if am == nil {
		return nil, handlers.NotFoundErrorf("Auth method %s not found.", req.GetAuthMethodId())
	}
	if am.GetApiUrl() == "" {
		return nil, handlers.InvalidArgumentErrorf("Auth method doesn't have API URL defined.", nil)
	}

	errRedirectBase := fmt.Sprintf(oidc.AuthenticationErrorsEndpoint, am.GetApiUrl())
	errResponse := func(err error) (*pbs.AuthenticateResponse, error) {
		u := make(url.Values)
		pbErr := handlers.ToApiError(err)
		out, err := handlers.JSONMarshaler().Marshal(pbErr)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to marshal the error for callback"))
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "unable to marshal the error for callback")
		}
		u.Add("error", string(out))
		errRedirect := fmt.Sprintf("%s?%s", errRedirectBase, u.Encode())
		return &pbs.AuthenticateResponse{
			Command: callbackCommand,
			Attrs: &pbs.AuthenticateResponse_OidcAuthMethodAuthenticateCallbackResponse{
				OidcAuthMethodAuthenticateCallbackResponse: &pb.OidcAuthMethodAuthenticateCallbackResponse{
					FinalRedirectUrl: errRedirect,
				},
			},
		}, nil
	}

	attrs := req.GetOidcAuthMethodAuthenticateCallbackRequest()

	var finalRedirectUrl string
	if attrs.GetError() != "" {
		err := errors.Wrap(ctx, fmt.Errorf("Error: %q, Details: %q", attrs.GetError(), attrs.GetErrorDescription()), op, errors.WithCode(errors.OidcProviderCallbackError))
		return errResponse(err)
	}
	finalRedirectUrl, err = oidc.Callback(
		ctx,
		s.oidcRepoFn,
		oidc.IamRepoFactory(s.iamRepoFn),
		s.atRepoFn,
		am,
		attrs.GetState(),
		attrs.GetCode())
	if err != nil {
		return errResponse(errors.New(ctx, errors.InvalidParameter, op, "Callback validation failed.", errors.WithWrap(err)))
	}

	return &pbs.AuthenticateResponse{
		Command: req.GetCommand(),
		Attrs: &pbs.AuthenticateResponse_OidcAuthMethodAuthenticateCallbackResponse{
			OidcAuthMethodAuthenticateCallbackResponse: &pb.OidcAuthMethodAuthenticateCallbackResponse{
				FinalRedirectUrl: finalRedirectUrl,
			},
		},
	}, nil
}

func (s Service) authenticateOidcToken(ctx context.Context, req *pbs.AuthenticateRequest, authResults *auth.VerifyResults) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).authenticateOidcToken"
	if req == nil {
		return nil, handlers.InvalidArgumentErrorf("Nil request.", nil)
	}
	if authResults == nil {
		return nil, handlers.InvalidArgumentErrorf("Nil auth results.", nil)
	}
	if req.GetOidcAuthMethodAuthenticateTokenRequest() == nil {
		return nil, handlers.InvalidArgumentErrorf("Nil request attributes.", nil)
	}

	attrs := req.GetOidcAuthMethodAuthenticateTokenRequest()
	if attrs.TokenId == "" {
		return nil, handlers.InvalidArgumentErrorf("Empty token ID in request attributes.", nil)
	}

	token, err := oidc.TokenRequest(ctx, s.kms, s.atRepoFn, req.GetAuthMethodId(), attrs.TokenId)
	if err != nil {
		switch {
		case errors.Match(errors.T(errors.Forbidden), err):
			return nil, handlers.ForbiddenError()
		case errors.Match(errors.T(errors.AuthAttemptExpired), err):
			return nil, handlers.ForbiddenError()
		default:
			event.WriteError(ctx, op, err, event.WithInfoMsg("error generating parameters for token request"))
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Error generating parameters for token request. See the controller's log for more information.")
		}
	}
	if token == nil {
		return &pbs.AuthenticateResponse{
			Command: req.Command,
			Attrs: &pbs.AuthenticateResponse_OidcAuthMethodAuthenticateTokenResponse{
				OidcAuthMethodAuthenticateTokenResponse: &pb.OidcAuthMethodAuthenticateTokenResponse{
					Status: "unknown",
				},
			},
		}, nil
	}

	responseToken, err := s.ConvertInternalAuthTokenToApiAuthToken(
		ctx,
		token,
	)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error converting response to proper format."))
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Error converting response to proper format. See the controller's log for more information.")
	}
	return s.convertToAuthenticateResponse(ctx, req, authResults, responseToken)
}

func validateAuthenticateOidcRequest(_ context.Context, req *pbs.AuthenticateRequest) error {
	badFields := make(map[string]string)

	switch req.GetCommand() {
	case startCommand:
		if req.GetOidcStartAttributes() != nil {
			attrs := req.GetOidcStartAttributes()
			switch {
			case attrs == nil:
				badFields["attributes"] = "Attributes field not supplied request"
			default:
				// Ensure we pay no attention to cache information provided by the client
				attrs.CachedRoundtripPayload = ""

				payload := attrs.GetRoundtripPayload()
				if payload == nil {
					break
				}
				m, err := json.Marshal(payload.AsMap())
				if err != nil {
					// We don't know what's in this payload so we swallow the
					// error, as it could be something sensitive.
					badFields[roundtripPayloadAttributesField] = "Unable to marshal given value as JSON."
				} else {
					// Cache for later
					attrs.CachedRoundtripPayload = string(m)
				}
			}
		}
	case callbackCommand:
		attrs := req.GetOidcAuthMethodAuthenticateCallbackRequest()
		switch {
		case attrs == nil:
			badFields["attributes"] = "Attributes field not supplied request"
			return handlers.InvalidArgumentErrorf("This is a required field.", badFields)
		default:
			if attrs.GetCode() == "" && attrs.GetError() == "" {
				badFields[codeField] = "Code field not supplied in callback request."
			}

			if attrs.GetState() == "" {
				badFields[stateField] = "State field not supplied in callback request."
			}
		}

	case tokenCommand:
		tokenType := req.GetType()
		if tokenType == "" {
			// Fall back to deprecated field if type is not set
			tokenType = req.GetTokenType()
		}
		tType := strings.ToLower(strings.TrimSpace(tokenType))
		if tType != "" && tType != "token" && tType != "cookie" {
			badFields[tokenTypeField] = `The only accepted types are "token" and "cookie".`
		}

	default:
		badFields[commandField] = "Invalid command for this auth method type."
	}

	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid fields provided in request.", badFields)
	}
	return nil
}

func toStorageOidcAuthMethod(ctx context.Context, scopeId string, in *pb.AuthMethod) (out *oidc.AuthMethod, dryRun, forced bool, err error) {
	const op = "authmethod_service.toStorageOidcAuthMethod"
	if in == nil {
		return nil, false, false, errors.New(ctx, errors.InvalidParameter, op, "nil auth method.")
	}
	attrs := in.GetOidcAuthMethodsAttributes()
	clientId := attrs.GetClientId().GetValue()
	clientSecret := oidc.ClientSecret(attrs.GetClientSecret().GetValue())

	var opts []oidc.Option
	if in.GetName() != nil {
		opts = append(opts, oidc.WithName(in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, oidc.WithDescription(in.GetDescription().GetValue()))
	}

	if iss := strings.TrimSpace(attrs.GetIssuer().GetValue()); iss != "" {
		// Strip off everything after and including ".well-known/openid-configuration"
		// but leave the "/" attached to the end.
		iss = strings.SplitN(iss, ".well-known/", 2)[0]
		iss, err := parseutil.NormalizeAddr(iss)
		if err != nil {
			return nil, false, false, errors.Wrap(ctx, err, op, errors.WithMsg("cannot normalize issuer"), errors.WithCode(errors.InvalidParameter))
		}
		issuer, err := url.Parse(iss)
		if err != nil {
			return nil, false, false, errors.Wrap(ctx, err, op, errors.WithMsg("cannot parse issuer"), errors.WithCode(errors.InvalidParameter))
		}
		opts = append(opts, oidc.WithIssuer(issuer))
	}
	if apiUrl := strings.TrimSpace(attrs.GetApiUrlPrefix().GetValue()); apiUrl != "" {
		apiUrl, err := parseutil.NormalizeAddr(apiUrl)
		if err != nil {
			return nil, false, false, errors.Wrap(ctx, err, op, errors.WithMsg("cannot normalize api_url_prefix"), errors.WithCode(errors.InvalidParameter))
		}
		apiU, err := url.Parse(apiUrl)
		if err != nil {
			return nil, false, false, errors.Wrap(ctx, err, op, errors.WithMsg("cannot parse api_url_prefix"), errors.WithCode(errors.InvalidParameter))
		}
		opts = append(opts, oidc.WithApiUrl(apiU))
	}

	if attrs.GetMaxAge() != nil {
		maxAge := attrs.GetMaxAge().GetValue()
		if maxAge == 0 {
			opts = append(opts, oidc.WithMaxAge(-1))
		} else {
			opts = append(opts, oidc.WithMaxAge(int(maxAge)))
		}
	}
	var signAlgs []oidc.Alg
	for _, a := range attrs.GetSigningAlgorithms() {
		signAlgs = append(signAlgs, oidc.Alg(a))
	}
	if len(signAlgs) > 0 {
		opts = append(opts, oidc.WithSigningAlgs(signAlgs...))
	}
	var prompts []oidc.PromptParam
	for _, a := range attrs.GetPrompts() {
		prompts = append(prompts, oidc.PromptParam(a))
	}
	if len(prompts) > 0 {
		opts = append(opts, oidc.WithPrompts(prompts...))
	}
	if len(attrs.GetAllowedAudiences()) > 0 {
		opts = append(opts, oidc.WithAudClaims(attrs.GetAllowedAudiences()...))
	}

	if len(attrs.GetIdpCaCerts()) > 0 {
		certs, err := oidc.ParseCertificates(ctx, attrs.GetIdpCaCerts()...)
		if err != nil {
			return nil, false, false, err
		}
		opts = append(opts, oidc.WithCertificates(certs...))
	}

	if len(attrs.GetClaimsScopes()) > 0 {
		opts = append(opts, oidc.WithClaimsScopes(attrs.GetClaimsScopes()...))
	}

	if len(attrs.GetAccountClaimMaps()) > 0 {
		claimsMap := make(map[string]oidc.AccountToClaim, len(attrs.GetAccountClaimMaps()))
		for _, v := range attrs.GetAccountClaimMaps() {
			acm, err := oidc.ParseAccountClaimMaps(ctx, v)
			if err != nil {
				return nil, false, false, errors.Wrap(ctx, err, op)
			}
			if len(acm) > 1 {
				return nil, false, false, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to parse account claim map %s", v))
			}
			var m oidc.ClaimMap
			for _, m = range acm {
			}
			to, err := oidc.ConvertToAccountToClaim(ctx, m.To)
			if err != nil {
				return nil, false, false, errors.Wrap(ctx, err, op)
			}
			claimsMap[m.From] = to
		}
		opts = append(opts, oidc.WithAccountClaimMap(claimsMap))
	}

	u, err := oidc.NewAuthMethod(ctx, scopeId, clientId, clientSecret, opts...)
	if err != nil {
		return nil, false, false, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method: %v.", err)
	}
	return u, attrs.GetDryRun(), attrs.GetDisableDiscoveredConfigValidation(), nil
}
