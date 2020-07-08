package authenticate

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/watchtower/internal/authtoken"
	pba "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/authtokens"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/common"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const orgIdFieldName = "org_id"

var (
	reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")
)

// Service handles request as described by the pbs.OrganizationServiceServer interface.
type Service struct {
	iamRepo       common.IamRepoFactory
	authTokenRepo common.AuthTokenRepoFactory
	authAcctId    string
}

// NewService returns an organization service which handles organization related requests to watchtower.
func NewService(iamRepo common.IamRepoFactory, atRepo common.AuthTokenRepoFactory, authAccountId string) (Service, error) {
	if iamRepo == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	if atRepo == nil {
		return Service{}, fmt.Errorf("nil auth token repository provided")
	}
	return Service{iamRepo: iamRepo, authTokenRepo: atRepo, authAcctId: authAccountId}, nil
}

var _ pbs.AuthenticationServiceServer = Service{}

// Authenticate implements the interface pbs.OrganizationServiceServer.
func (s Service) Authenticate(ctx context.Context, req *pbs.AuthenticateRequest) (*pbs.AuthenticateResponse, error) {
	if err := validateAuthenticateRequest(req); err != nil {
		return nil, err
	}
	tok, err := s.authenticateWithRepo(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pbs.AuthenticateResponse{Item: tok}, nil
}

// Deauthenticate implements the interface pbs.OrganizationServiceServer.
func (s Service) Deauthenticate(ctx context.Context, req *pbs.DeauthenticateRequest) (*pbs.DeauthenticateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Requested method is unimplemented for Organization.")
}

func (s Service) authenticateWithRepo(ctx context.Context, req *pbs.AuthenticateRequest) (*pba.AuthToken, error) {
	userRepo, err := s.iamRepo()
	if err != nil {
		return nil, err
	}
	atRepo, err := s.authTokenRepo()
	if err != nil {
		return nil, err
	}
	// Place holder for making a request to authenticate
	creds := req.GetCredentials().GetFields()
	pwName, password := creds["name"], creds["password"]
	if s.authAcctId == "" || (pwName.GetStringValue() == "wrong" && password.GetStringValue() == "wrong") {
		return nil, status.Error(codes.Unauthenticated, "Unable to authenticate.")
	}
	// Get back a password.Account with a CredentialId string and a public Id
	u, err := userRepo.LookupUserWithLogin(ctx, s.authAcctId, iam.WithAutoVivify(true))
	if err != nil {
		return nil, err
	}
	tok, err := atRepo.CreateAuthToken(ctx, u.GetPublicId(), s.authAcctId)
	if err != nil {
		return nil, err
	}
	tok.Token = tok.GetPublicId() + "_" + tok.GetToken()
	return toProto(tok), nil
}

func toProto(t *authtoken.AuthToken) *pba.AuthToken {
	return &pba.AuthToken{
		Id:                      t.GetPublicId(),
		Token:                   t.GetToken(),
		UserId:                  t.GetIamUserId(),
		AuthMethodId:            t.GetAuthMethodId(),
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
	if !validId(req.GetOrgId(), scope.Organization.Prefix()+"_") {
		badFields[orgIdFieldName] = "Invalid formatted identifier."
	}
	if strings.TrimSpace(req.GetAuthMethodId()) == "" {
		badFields["auth_method_id"] = "This is a required field."
	} else if validId(req.GetAuthMethodId(), "am") {
		badFields["auth_method_id"] = "Invalid formatted identifier."
	}
	// TODO: Update this when we enable different auth method types.
	if req.GetCredentials() == nil {
		badFields["credentials"] = "This is a required field."
	}
	// TODO: Update this when we enable split cookie token types.
	tType := strings.ToLower(strings.TrimSpace(req.GetTokenType()))
	if tType != "" && tType != "token" {
		badFields["token_type"] = "The only accepted type is 'token'."
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
