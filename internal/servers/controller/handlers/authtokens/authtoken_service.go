package authtokens

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service handles request as described by the pbs.AuthTokenServiceServer interface.
type Service struct {
	repoFn    common.AuthTokenRepoFactory
	iamRepoFn common.IamRepoFactory
}

// NewService returns a user service which handles user related requests to boundary.
func NewService(repo common.AuthTokenRepoFactory, iamRepoFn common.IamRepoFactory) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil auth token repository provided")
	}
	if iamRepoFn == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repoFn: repo, iamRepoFn: iamRepoFn}, nil
}

var _ pbs.AuthTokenServiceServer = Service{}

// ListAuthTokens implements the interface pbs.AuthTokenServiceServer.
func (s Service) ListAuthTokens(ctx context.Context, req *pbs.ListAuthTokensRequest) (*pbs.ListAuthTokensResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.pinAndAuthResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	ul, err := s.listFromRepo(ctx, req.GetScopeId())
	if err != nil {
		return nil, err
	}
	for _, item := range ul {
		item.Scope = authResults.Scope
	}
	return &pbs.ListAuthTokensResponse{Items: ul}, nil
}

// GetAuthToken implements the interface pbs.AuthTokenServiceServer.
func (s Service) GetAuthToken(ctx context.Context, req *pbs.GetAuthTokenRequest) (*pbs.GetAuthTokenResponse, error) {
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.pinAndAuthResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.GetAuthTokenResponse{Item: u}, nil
}

// DeleteAuthToken implements the interface pbs.AuthTokenServiceServer.
func (s Service) DeleteAuthToken(ctx context.Context, req *pbs.DeleteAuthTokenRequest) (*pbs.DeleteAuthTokenResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.pinAndAuthResult(ctx, req.GetId(), action.Delete)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	existed, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteAuthTokenResponse{Existed: existed}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.AuthToken, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	u, err := repo.LookupAuthToken(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("AuthToken %q doesn't exist.", id)
		}
		return nil, err
	}
	if u == nil {
		return nil, handlers.NotFoundErrorf("AuthToken %q doesn't exist.", id)
	}
	return toProto(u), nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteAuthToken(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return false, nil
		}
		return false, status.Errorf(codes.Internal, "Unable to delete user: %v.", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, orgId string) ([]*pb.AuthToken, error) {
	repo, err := s.repoFn()
	_ = repo
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListAuthTokens(ctx, orgId)
	if err != nil {
		return nil, err
	}
	var outUl []*pb.AuthToken
	for _, u := range ul {
		outUl = append(outUl, toProto(u))
	}
	return outUl, nil
}

func (s Service) pinAndAuthResult(ctx context.Context, id string, a action.Type) (*iam.Scope, auth.VerifyResults) {
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}
	iamRepo, err := s.iamRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}

	var scp *iam.Scope
	opts := []auth.Option{auth.WithType(resource.AuthToken), auth.WithAction(a)}
	switch a {
	case action.List:
		fallthrough
	case action.Create:
		scp, err = iamRepo.LookupScope(ctx, id)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if scp == nil {
			res.Error = handlers.ForbiddenError()
			return nil, res
		}
		opts = append(opts, auth.WithScopeId(id))
	default:
		// If the action isn't one of the above ones, than it is an action on an individual resource and the
		// id provided is for the resource itself.
		authTok, err := repo.LookupAuthToken(ctx, id)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if authTok == nil {
			res.Error = handlers.ForbiddenError()
			return nil, res
		}

		scp, err = iamRepo.LookupScope(ctx, authTok.GetScopeId())
		if err != nil {
			res.Error = err
			return nil, res
		}
		if scp == nil {
			res.Error = handlers.ForbiddenError()
			return nil, res
		}
		opts = append(opts, auth.WithId(id), auth.WithScopeId(scp.GetPublicId()))
	}
	authResults := auth.Verify(ctx, opts...)
	return scp, authResults
}

func toProto(in *authtoken.AuthToken) *pb.AuthToken {
	out := pb.AuthToken{
		Id:                      in.GetPublicId(),
		ScopeId:                 in.GetScopeId(),
		CreatedTime:             in.GetCreateTime().GetTimestamp(),
		UpdatedTime:             in.GetUpdateTime().GetTimestamp(),
		ApproximateLastUsedTime: in.GetApproximateLastAccessTime().GetTimestamp(),
		ExpirationTime:          in.GetExpirationTime().GetTimestamp(),
		UserId:                  in.GetIamUserId(),
		AuthMethodId:            in.GetAuthMethodId(),
	}
	return &out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetAuthTokenRequest) error {
	return handlers.ValidateGetRequest(authtoken.AuthTokenPrefix, req, handlers.NoopValidatorFn)
}

func validateDeleteRequest(req *pbs.DeleteAuthTokenRequest) error {
	return handlers.ValidateDeleteRequest(authtoken.AuthTokenPrefix, req, handlers.NoopValidatorFn)
}

func validateListRequest(req *pbs.ListAuthTokensRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(scope.Org.Prefix(), req.GetScopeId()) {
		badFields["scope_id"] = "Incorrectly formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}
