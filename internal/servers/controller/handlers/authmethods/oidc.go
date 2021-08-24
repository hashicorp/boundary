package authmethods

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	oidcstore "github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
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
)

var oidcMaskManager handlers.MaskManager

func init() {
	var err error
	if oidcMaskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&oidcstore.AuthMethod{}}, handlers.MaskSource{&pb.AuthMethod{}, &pb.OidcAuthMethodAttributes{}}); err != nil {
		panic(err)
	}

	IdActions[oidc.Subtype] = action.ActionSet{
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
		action.ChangeState,
		action.Authenticate,
	}
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

	return &pbs.AuthenticateResponse{Command: req.GetCommand(), Attributes: nil}, nil
}

func (s Service) authenticateOidcStart(ctx context.Context, req *pbs.AuthenticateRequest) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).authenticateOidcStart"
	if req == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Nil request.")
	}

	var opts []oidc.Option
	attrs := new(pbs.OidcStartAttributes)
	if err := handlers.StructToProto(req.GetAttributes(), attrs); err != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Error parsing request attributes.", errors.WithWrap(err))
	}
	if attrs.GetCachedRoundtripPayload() != "" {
		opts = append(opts, oidc.WithRoundtripPayload(attrs.GetCachedRoundtripPayload()))
	}

	authUrl, tokenId, err := oidc.StartAuth(ctx, s.oidcRepoFn, req.GetAuthMethodId(), opts...)
	if err != nil {
		// this event.WriteError(...) may cause a dup error to be emitted...
		// it should be removed if that's the case.
		event.WriteError(ctx, op, err, event.WithInfoMsg("error starting the oidc authentication flow"))
		return nil, errors.New(ctx, errors.Internal, op, "Error generating parameters for starting the OIDC flow. See the controller's log for more information.")
	}

	respAttrs := &pb.OidcAuthMethodAuthenticateStartResponse{
		AuthUrl: authUrl.String(),
		TokenId: tokenId,
	}
	resp := &pbs.AuthenticateResponse{Command: req.GetCommand()}
	if resp.Attributes, err = handlers.ProtoToStruct(respAttrs); err != nil {
		return nil, errors.New(ctx, errors.Internal, op, "Error marshaling parameters.", errors.WithWrap(err))
	}
	return resp, nil
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
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Nil request.")
	}

	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	am, err := repo.LookupAuthMethod(ctx, req.GetAuthMethodId())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if am == nil {
		return nil, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("Auth method %s not found.", req.GetAuthMethodId()))
	}
	if am.GetApiUrl() == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Auth method doesn't have API URL defined.")
	}

	errRedirectBase := fmt.Sprintf(oidc.AuthenticationErrorsEndpoint, am.GetApiUrl())
	errResponse := func(err error) (*pbs.AuthenticateResponse, error) {
		u := make(url.Values)
		pbErr := handlers.ToApiError(err)
		out, err := handlers.JSONMarshaler().Marshal(pbErr)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to marshal the error for callback"))
		}
		u.Add("error", string(out))
		errRedirect := fmt.Sprintf("%s?%s", errRedirectBase, u.Encode())
		respAttrs, err := handlers.ProtoToStruct(&pb.OidcAuthMethodAuthenticateCallbackResponse{
			FinalRedirectUrl: errRedirect,
		})
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed creating error redirect response"))
		}
		return &pbs.AuthenticateResponse{Command: callbackCommand, Attributes: respAttrs}, nil
	}

	attrs := new(pb.OidcAuthMethodAuthenticateCallbackRequest)
	// Note that this conversion has already happened in the validate call so we don't expect errors here.
	if err := handlers.StructToProto(req.GetAttributes(), attrs, handlers.WithDiscardUnknownFields(true)); err != nil {
		return errResponse(err)
	}

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

	respAttrs, err := handlers.ProtoToStruct(&pb.OidcAuthMethodAuthenticateCallbackResponse{
		FinalRedirectUrl: finalRedirectUrl,
	})
	if err != nil {
		return errResponse(errors.New(ctx, errors.Internal, op, "Error marshaling parameters after successful callback", errors.WithWrap(err)))
	}

	return &pbs.AuthenticateResponse{Command: req.GetCommand(), Attributes: respAttrs}, nil
}

func (s Service) authenticateOidcToken(ctx context.Context, req *pbs.AuthenticateRequest, authResults *auth.VerifyResults) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).authenticateOidcToken"
	if req == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Nil request.")
	}
	if authResults == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Nil auth results.")
	}
	if req.GetAttributes() == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Nil request attributes.")
	}

	attrs := new(pb.OidcAuthMethodAuthenticateTokenRequest)
	if err := handlers.StructToProto(req.GetAttributes(), attrs); err != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Error parsing request attributes.", errors.WithWrap(err))
	}
	if attrs.TokenId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "Empty token ID in request attributes.")
	}

	token, err := oidc.TokenRequest(ctx, s.kms, s.atRepoFn, req.GetAuthMethodId(), attrs.TokenId)
	if err != nil {
		switch {
		case errors.Match(errors.T(errors.Forbidden), err):
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Forbidden."))
		case errors.Match(errors.T(errors.AuthAttemptExpired), err):
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Forbidden."))
		default:
			// this event.WriteError(...) may cause a dup error to be emitted...
			// it should be removed if that's the case.
			event.WriteError(ctx, op, err, event.WithInfoMsg("error generating parameters for token request"))
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Error generating parameters for token request. See the controller's log for more information."))
		}
	}
	if token == nil {
		attrs, err := structpb.NewStruct(map[string]interface{}{
			statusField: "unknown",
		})
		if err != nil {
			return nil, errors.New(ctx, errors.Internal, op, "Error generating response attributes.", errors.WithWrap(err))
		}
		return &pbs.AuthenticateResponse{
			Command:    req.Command,
			Attributes: attrs,
		}, nil
	}

	responseToken, err := s.ConvertInternalAuthTokenToApiAuthToken(
		ctx,
		token,
	)
	if err != nil {
		return nil, errors.New(ctx, errors.Internal, op, "Error converting response to proper format.", errors.WithWrap(err))
	}
	return s.convertToAuthenticateResponse(ctx, req, authResults, responseToken)
}

func validateAuthenticateOidcRequest(req *pbs.AuthenticateRequest) error {
	badFields := make(map[string]string)

	switch req.GetCommand() {
	case startCommand:
		if req.GetAttributes() != nil {
			attrs := new(pbs.OidcStartAttributes)
			if err := handlers.StructToProto(req.GetAttributes(), attrs); err != nil {
				badFields[attributesField] = "Could not be parsed, or contains invalid fields."
				break
			}

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
				req.Attributes, err = handlers.ProtoToStruct(attrs)
				if err != nil {
					return fmt.Errorf("unable to convert map back to proto")
				}
			}
		}
	case callbackCommand:
		if req.GetAttributes() == nil {
			badFields[attributesField] = "No callback attributes provided."
			break
		}

		attrs := new(pb.OidcAuthMethodAuthenticateCallbackRequest)
		if err := handlers.StructToProto(req.GetAttributes(), attrs, handlers.WithDiscardUnknownFields(true)); err != nil {
			badFields[attributesField] = "Unable to parse callback request attributes."
			break
		}

		if attrs.GetCode() == "" && attrs.GetError() == "" {
			badFields[codeField] = "Code field not supplied in callback request."
		}

		if attrs.GetState() == "" {
			badFields[stateField] = "State field not supplied in callback request."
		}

	case tokenCommand:
		tType := strings.ToLower(strings.TrimSpace(req.GetTokenType()))
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
		return nil, false, false, errors.NewDeprecated(errors.InvalidParameter, op, "nil auth method.")
	}
	attrs := &pb.OidcAuthMethodAttributes{}
	if err := handlers.StructToProto(in.GetAttributes(), attrs); err != nil {
		return nil, false, false, handlers.InvalidArgumentErrorf("Error in provided request.",
			map[string]string{attributesField: "Attribute fields do not match the expected format."})
	}
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
		issuer, err := url.Parse(iss)
		if err != nil {
			return nil, false, false, errors.WrapDeprecated(err, op, errors.WithMsg("cannot parse issuer"), errors.WithCode(errors.InvalidParameter))
		}
		opts = append(opts, oidc.WithIssuer(issuer))
	}
	if apiUrl := strings.TrimSpace(attrs.GetApiUrlPrefix().GetValue()); apiUrl != "" {
		apiU, err := url.Parse(apiUrl)
		if err != nil {
			return nil, false, false, errors.WrapDeprecated(err, op, errors.WithMsg("cannot parse api_url_prefix"), errors.WithCode(errors.InvalidParameter))
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
				return nil, false, false, errors.WrapDeprecated(err, op)
			}
			if len(acm) > 1 {
				return nil, false, false, errors.NewDeprecated(errors.InvalidParameter, op, fmt.Sprintf("unable to parse account claim map %s", v))
			}
			var m oidc.ClaimMap
			for _, m = range acm {
			}
			to, err := oidc.ConvertToAccountToClaim(ctx, m.To)
			if err != nil {
				return nil, false, false, errors.WrapDeprecated(err, op)
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
