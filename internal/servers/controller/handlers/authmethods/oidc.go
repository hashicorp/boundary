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
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/authtokens"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// commands
	startCommand    = "start"
	callbackCommand = "callback"
	tokenCommand    = "token"

	// field names
	issuerField                            = "attributes.issuer"
	clientSecretField                      = "attributes.client_secret"
	clientIdField                          = "attributes.client_id"
	clientSecretHmacField                  = "attributes.client_secret_hmac"
	stateField                             = "attributes.state"
	callbackUrlField                       = "attributes.callback_url"
	apiUrlPrefixeField                     = "attributes.api_url_prefixes"
	caCertsField                           = "attributes.ca_certs"
	maxAgeField                            = "attributes.max_age"
	signingAlgorithmField                  = "attributes.signing_algorithms"
	disableDiscoveredConfigValidationField = "attributes.disable_discovered_config_validation"
	roundtripPayloadField                  = "attributes.roundtrip_payload"
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
	switch req.GetCommand() {
	case startCommand:
		return s.authenticateOidcStart(ctx, req, authResults)
	}
	reqAttrs := req.GetAttributes().GetFields()
	tok, err := s.authenticateWithPwRepo(ctx, authResults.Scope.GetId(), req.GetAuthMethodId(), reqAttrs[loginNameField].GetStringValue(), reqAttrs[passwordField].GetStringValue())
	if err != nil {
		return nil, err
	}
	res := &perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.AuthToken,
	}
	tok.AuthorizedActions = authResults.FetchActionSetForId(ctx, tok.Id, authtokens.IdActions, auth.WithResource(res)).Strings()
	retAttrs, err := handlers.ProtoToStruct(tok)
	if err != nil {
		return nil, err
	}
	retAttrs.GetFields()[tokenTypeField] = structpb.NewStringValue(req.GetTokenType())
	return &pbs.AuthenticateResponse{Command: req.GetCommand(), Attributes: retAttrs}, nil
}

func (s Service) authenticateOidcStart(ctx context.Context, req *pbs.AuthenticateRequest, authResults *auth.VerifyResults) (*pbs.AuthenticateResponse, error) {
	const op = "authmethod_service.(Service).authenticateOidcStart"
	var opts []oidc.Option
	if req.GetAttributes() != nil && req.GetAttributes().GetFields() != nil {
		if val, ok := req.GetAttributes().GetFields()[roundtripPayloadField]; ok {
			structVal := val.GetStructValue()
			if structVal != nil {
				m, err := json.Marshal(structVal)
				if err != nil {
					// We don't know what's in this payload so we swallow the
					// error, as it could be something sensitive.
					return nil, errors.New(errors.InvalidParameter, op, "Unable to marshal attrs.roundtrip_payload as JSON")
				}
				opts = append(opts, oidc.WithRoundtripPayload(string(m)))
			}
		}
	}
	return nil, nil
}

func validateAuthenticateOidcRequest(req *pbs.AuthenticateRequest) error {
	badFields := make(map[string]string)

	switch req.GetCommand() {
	case startCommand:
	case callbackCommand:
	case tokenCommand:
		tType := strings.ToLower(strings.TrimSpace(req.GetTokenType()))
		if tType != "" && tType != "token" && tType != "cookie" {
			badFields[tokenTypeField] = `The only accepted types are "token" and "cookie".`
		}
	default:
		badFields["command"] = "Invalid command for this auth method type."
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

	var discoveryUrl *url.URL
	if ds := attrs.GetIssuer().GetValue(); ds != "" {
		var err error
		if discoveryUrl, err = url.Parse(ds); err != nil {
			return nil, false, err
		}
		// remove everything except for protocol, hostname, and port.
		if discoveryUrl, err = discoveryUrl.Parse("/"); err != nil {
			return nil, false, err
		}
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

	if attrs.GetApiUrlPrefix().GetValue() != "" {
		apiU, err := url.Parse(attrs.GetApiUrlPrefix().GetValue())
		if err != nil {
			return nil, false, handlers.InvalidArgumentErrorf("Error in provided request",
				map[string]string{apiUrlPrefixeField: "Unparsable url"})
		}
		opts = append(opts, oidc.WithCallbackUrls(apiU))
	}

	if len(attrs.GetCaCerts()) > 0 {
		certs, err := oidc.ParseCertificates(attrs.GetCaCerts()...)
		if err != nil {
			return nil, false, err
		}
		opts = append(opts, oidc.WithCertificates(certs...))
	}

	u, err := oidc.NewAuthMethod(scopeId, discoveryUrl, clientId, clientSecret, opts...)
	if err != nil {
		return nil, false, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method: %v.", err)
	}
	return u, attrs.DisableDiscoveredConfigValidation, nil
}
