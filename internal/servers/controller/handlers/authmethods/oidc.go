package authmethods

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	oidcstore "github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
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
	tokenField = "token"

	// field names
	issuerField                            = "attributes.issuer"
	clientSecretField                      = "attributes.client_secret"
	clientIdField                          = "attributes.client_id"
	clientSecretHmacField                  = "attributes.client_secret_hmac"
	stateField                             = "attributes.state"
	callbackUrlField                       = "attributes.callback_url"
	apiUrlPrefixField                      = "attributes.api_url_prefix"
	caCertsField                           = "attributes.ca_certs"
	maxAgeField                            = "attributes.max_age"
	signingAlgorithmField                  = "attributes.signing_algorithms"
	disableDiscoveredConfigValidationField = "attributes.disable_discovered_config_validation"
	roundtripPayloadAttributesField        = "attributes.roundtrip_payload"
	codeField                              = "attributes.code"
)

var oidcMaskManager handlers.MaskManager

func init() {
	var err error
	if oidcMaskManager, err = handlers.NewMaskManager(&oidcstore.AuthMethod{}, &pb.AuthMethod{}, &pb.OidcAuthMethodAttributes{}); err != nil {
		panic(err)
	}

	IdActions[auth.OidcSubtype] = action.ActionSet{
		action.Read,
		action.Update,
		action.Delete,
		action.ChangeState,
		action.Authenticate,
	}
}

type oidcState uint

const (
	unknownState oidcState = iota
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
	u, _, err := toStorageOidcAuthMethod(scopeId, item)
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

func (s Service) updateOidcInRepo(ctx context.Context, scopeId string, req *pbs.UpdateAuthMethodRequest) (*oidc.AuthMethod, error) {
	item := req.GetItem()
	u, forced, err := toStorageOidcAuthMethod(scopeId, item)
	if err != nil {
		return nil, err
	}
	u.PublicId = req.GetId()

	var opts []oidc.Option
	if forced {
		opts = append(opts, oidc.WithForce())
	}

	version := item.GetVersion()
	dbMask := oidcMaskManager.Translate(req.GetUpdateMask().GetPaths())
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}

	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateAuthMethod(ctx, u, version, dbMask, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to update auth method: %w", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist or incorrect version provided.", req.GetId())
	}
	return out, nil
}

func (s Service) authenticateOidc(ctx context.Context, req *pbs.AuthenticateRequest, authResults *auth.VerifyResults) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).authenticateOidc"
	if req == nil {
		return nil, errors.New(errors.InvalidParameter, op, "Nil request.")
	}
	if authResults == nil {
		return nil, errors.New(errors.InvalidParameter, op, "Nil auth results.")
	}
	switch req.GetCommand() {
	case startCommand:
		return s.authenticateOidcStart(ctx, req, authResults)
	case callbackCommand:
		return s.authenticateOidcCallback(ctx, req, authResults)
	case tokenCommand:
		return s.authenticateOidcToken(ctx, req, authResults)
	}

	// Default is tokenCommand -- note we've already checked that it's one of
	// these three in the validation function
	// TODO
	return &pbs.AuthenticateResponse{Command: req.GetCommand(), Attributes: nil}, nil
}

func (s Service) authenticateOidcStart(ctx context.Context, req *pbs.AuthenticateRequest, authResults *auth.VerifyResults) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).authenticateOidcStart"
	if req == nil {
		return nil, errors.New(errors.InvalidParameter, op, "Nil request.")
	}
	if authResults == nil {
		return nil, errors.New(errors.InvalidParameter, op, "Nil auth results.")
	}

	var opts []oidc.Option
	if req.GetAttributes() != nil {
		attrs := new(pbs.OidcStartAttributes)
		if err := handlers.StructToProto(req.GetAttributes(), attrs); err != nil {
			return nil, errors.New(errors.InvalidParameter, op, "Error parsing request attributes.")
		}
		if attrs.GetCachedRoundtripPayload() != "" {
			opts = append(opts, oidc.WithRoundtripPayload(attrs.GetCachedRoundtripPayload()))
		}
	}

	authUrl, tokenUrl, tokenId, err := oidc.StartAuth(ctx, s.oidcRepoFn, req.GetAuthMethodId(), opts...)
	if err != nil {
		// TODO: Log something
		return nil, errors.New(errors.Internal, op, "Error generating parameters for starting the OIDC flow.")
	}

	resp := &pb.OidcAuthMethodAuthenticateStartResponse{
		AuthUrl:  authUrl.String(),
		TokenUrl: tokenUrl.String(),
		TokenId:  tokenId,
	}

	attrs, err := handlers.ProtoToStruct(resp)
	if err != nil {
		return nil, errors.New(errors.Internal, op, "Error marshaling parameters.")
	}

	return &pbs.AuthenticateResponse{Command: req.GetCommand(), Attributes: attrs}, nil
}

func (s Service) authenticateOidcCallback(ctx context.Context, req *pbs.AuthenticateRequest, authResults *auth.VerifyResults) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).authenticateOidcCallback"
	if req == nil {
		return nil, errors.New(errors.InvalidParameter, op, "Nil request.")
	}
	if authResults == nil {
		return nil, errors.New(errors.InvalidParameter, op, "Nil auth results.")
	}

	attrs := new(pb.OidcAuthMethodAuthenticateCallbackRequest)
	// Note that this conversion has already happened in the validate call so we don't expect errors here.
	if err := handlers.StructToProto(req.GetAttributes(), attrs, handlers.WithDiscardUnknownFields(true)); err != nil {
		return nil, err
	}

	_, err := oidc.Callback(
		ctx,
		s.oidcRepoFn,
		oidc.IamRepoFactory(s.iamRepoFn),
		s.atRepoFn,
		req.GetAuthMethodId(),
		attrs.GetState(),
		attrs.GetCode())
	if err != nil {
		// TODO: Log something more meaningful
		return nil, errors.New(errors.InvalidParameter, op, "Callback validation failed.")
	}

	return nil, handlers.ApiErrorWithCode(codes.Unimplemented)
}

func (s Service) authenticateOidcToken(ctx context.Context, req *pbs.AuthenticateRequest, authResults *auth.VerifyResults) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).authenticateOidcToken"
	if req == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil request")
	}
	if authResults == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil auth results")
	}
	if req.GetAttributes() == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil request attributes")
	}

	attrs := new(pb.OidcAuthMethodAuthenticateTokenRequest)
	if err := handlers.StructToProto(req.GetAttributes(), attrs); err != nil {
		return nil, errors.New(errors.InvalidParameter, op, "error parsing request attributes")
	}
	if attrs.TokenId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "empty token id request attributes")
	}

	token, err := oidc.TokenRequest(ctx, s.kms, s.atRepoFn, attrs.TokenId)
	if err != nil {
		// TODO: Log something so we don't lose the error's context and entire msg...
		switch {
		case errors.Match(errors.T(errors.Forbidden), err):
			return nil, errors.Wrap(err, op, errors.WithMsg("Forbidden"))
		case errors.Match(errors.T(errors.AuthAttemptExpired), err):
			return nil, errors.Wrap(err, op, errors.WithMsg("Forbidden"))
		default:
			return nil, errors.Wrap(err, op)
		}
	}

	attrsMap := map[string]interface{}{
		tokenField:     token,
		tokenTypeField: req.GetTokenType(),
	}

	respAttrs, err := structpb.NewStruct(attrsMap)
	if err != nil {
		return nil, errors.New(errors.Internal, op, "Error marshaling parameters.")
	}

	return &pbs.AuthenticateResponse{Command: req.GetCommand(), Attributes: respAttrs}, nil
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
					// TODO: Logging, when we have a logger
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

		if attrs.GetError() != "" {
			// TODO: Log more info.
			return handlers.ApiErrorWithCodeAndMessage(codes.Unauthenticated, "OIDC provider returned an error.")
		}

		if attrs.GetCode() == "" {
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

func toStorageOidcAuthMethod(scopeId string, in *pb.AuthMethod) (out *oidc.AuthMethod, forced bool, err error) {
	const op = "authmethod_service.toStorageOidcAuthMethod"
	if in == nil {
		return nil, false, errors.New(errors.InvalidParameter, op, "nil auth method.")
	}
	attrs := &pb.OidcAuthMethodAttributes{}
	if err := handlers.StructToProto(in.GetAttributes(), attrs); err != nil {
		return nil, false, handlers.InvalidArgumentErrorf("Error in provided request.",
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
		var issuer *url.URL
		var err error
		if issuer, err = url.Parse(iss); err != nil {
			return nil, false, err
		}
		// remove everything except for protocol, hostname, and port.
		if issuer, err = issuer.Parse("/"); err != nil {
			return nil, false, err
		}
		opts = append(opts, oidc.WithIssuer(issuer))
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

	if apiUrl := strings.TrimSpace(attrs.GetApiUrlPrefix().GetValue()); apiUrl != "" {
		apiU, err := url.Parse(apiUrl)
		if err != nil {
			return nil, false, handlers.InvalidArgumentErrorf("Error in provided request",
				map[string]string{apiUrlPrefixField: "Unparsable url"})
		}
		opts = append(opts, oidc.WithApiUrl(apiU))
	}

	if len(attrs.GetIdpCaCerts()) > 0 {
		certs, err := oidc.ParseCertificates(attrs.GetIdpCaCerts()...)
		if err != nil {
			return nil, false, err
		}
		opts = append(opts, oidc.WithCertificates(certs...))
	}

	u, err := oidc.NewAuthMethod(scopeId, clientId, clientSecret, opts...)
	if err != nil {
		return nil, false, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method: %v.", err)
	}
	return u, attrs.DisableDiscoveredConfigValidation, nil
}
