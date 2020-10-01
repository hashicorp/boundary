package authenticate

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/authtoken"
	pba "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/grpc/codes"
)

const (
	loginNameKey = "login_name"
	pwKey        = "password"
)

var (
	reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")
)

// Service handles request as described by the pbs.OrgServiceServer interface.
type Service struct {
	kms           *kms.Kms
	pwRepo        common.PasswordAuthRepoFactory
	iamRepo       common.IamRepoFactory
	authTokenRepo common.AuthTokenRepoFactory
}

// NewService returns an org service which handles org related requests to boundary.
func NewService(kms *kms.Kms, pwRepo common.PasswordAuthRepoFactory, iamRepo common.IamRepoFactory, atRepo common.AuthTokenRepoFactory) (Service, error) {
	if kms == nil {
		return Service{}, errors.New("nil kms provided")
	}
	if iamRepo == nil {
		return Service{}, errors.New("nil iam repository provided")
	}
	if atRepo == nil {
		return Service{}, errors.New("nil auth token repository provided")
	}
	if pwRepo == nil {
		return Service{}, errors.New("nil password repository provided")
	}

	return Service{kms: kms, pwRepo: pwRepo, iamRepo: iamRepo, authTokenRepo: atRepo}, nil
}

var _ pbs.AuthenticationServiceServer = Service{}

// Authenticate implements the interface pbs.AuthenticationServiceServer.
func (s Service) Authenticate(ctx context.Context, req *pbs.AuthenticateRequest) (*pbs.AuthenticateResponse, error) {
	if err := validateAuthenticateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetAuthMethodId(), action.Authenticate)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	creds := req.GetCredentials().GetFields()
	tok, err := s.authenticateWithRepo(ctx, authResults.Scope.GetId(), req.GetAuthMethodId(), creds[loginNameKey].GetStringValue(), creds[pwKey].GetStringValue())
	if err != nil {
		return nil, err
	}
	return &pbs.AuthenticateResponse{Item: tok, TokenType: req.GetTokenType()}, nil
}

func (s Service) authenticateWithRepo(ctx context.Context, scopeId, authMethodId, loginName, pw string) (*pba.AuthToken, error) {
	iamRepo, err := s.iamRepo()
	if err != nil {
		return nil, err
	}
	atRepo, err := s.authTokenRepo()
	if err != nil {
		return nil, err
	}
	pwRepo, err := s.pwRepo()
	if err != nil {
		return nil, err
	}

	acct, err := pwRepo.Authenticate(ctx, scopeId, authMethodId, loginName, pw)
	if err != nil {
		return nil, err
	}
	if acct == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Unauthenticated, "Unable to authenticate.")
	}

	u, err := iamRepo.LookupUserWithLogin(ctx, acct.GetPublicId(), iam.WithAutoVivify(true))
	if err != nil {
		return nil, err
	}
	tok, err := atRepo.CreateAuthToken(ctx, u, acct.GetPublicId())
	if err != nil {
		return nil, err
	}

	token, err := authtoken.EncryptToken(ctx, s.kms, scopeId, tok.GetPublicId(), tok.GetToken())
	if err != nil {
		return nil, err
	}

	tok.Token = tok.GetPublicId() + "_" + token
	prot := toProto(tok)

	scp, err := iamRepo.LookupScope(ctx, u.GetScopeId())
	if err != nil {
		return nil, err
	}
	if scp == nil {
		return nil, err
	}
	prot.Scope = &scopes.ScopeInfo{
		Id:            scp.GetPublicId(),
		Type:          scp.GetType(),
		ParentScopeId: scp.GetParentId(),
	}

	return prot, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	res := auth.VerifyResults{}

	repo, err := s.pwRepo()
	if err != nil {
		res.Error = err
		return res
	}
	authMeth, err := repo.LookupAuthMethod(ctx, id)
	if err != nil {
		res.Error = err
		return res
	}
	if authMeth == nil {
		res.Error = handlers.NotFoundError()
		return res
	}

	authResults := auth.Verify(ctx,
		auth.WithAction(a),
		auth.WithType(resource.AuthMethod),
		auth.WithScopeId(authMeth.GetScopeId()),
		auth.WithId(id))
	return authResults
}

func toProto(t *authtoken.AuthToken) *pba.AuthToken {
	return &pba.AuthToken{
		Id:                      t.GetPublicId(),
		Token:                   t.GetToken(),
		UserId:                  t.GetIamUserId(),
		AuthMethodId:            t.GetAuthMethodId(),
		AccountId:               t.GetAuthAccountId(),
		CreatedTime:             t.GetCreateTime().GetTimestamp(),
		UpdatedTime:             t.GetUpdateTime().GetTimestamp(),
		ApproximateLastUsedTime: t.GetApproximateLastAccessTime().GetTimestamp(),
		ExpirationTime:          t.GetExpirationTime().GetTimestamp(),
	}
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateAuthenticateRequest(req *pbs.AuthenticateRequest) error {
	badFields := make(map[string]string)
	if strings.TrimSpace(req.GetAuthMethodId()) == "" {
		badFields["auth_method_id"] = "This is a required field."
	} else if validId(req.GetAuthMethodId(), "am") {
		badFields["auth_method_id"] = "Invalid formatted identifier."
	}
	// TODO: Update this when we enable different auth method types.
	if req.GetCredentials() == nil {
		badFields["credentials"] = "This is a required field."
	}
	creds := req.GetCredentials().GetFields()
	if _, ok := creds[loginNameKey]; !ok {
		badFields["credentials.login_name"] = "This is a required field."
	}
	if _, ok := creds[pwKey]; !ok {
		badFields["credentials.password"] = "This is a required field."
	}
	tType := strings.ToLower(strings.TrimSpace(req.GetTokenType()))
	if tType != "" && tType != "token" && tType != "cookie" {
		badFields["token_type"] = `The only accepted types are "token" and "cookie".`
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid fields provided in request.", badFields)
	}
	return nil
}

func validId(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) {
		return false
	}
	id = strings.TrimPrefix(id, prefix)
	return !reInvalidID.Match([]byte(id))
}
