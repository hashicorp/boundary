package users

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/vault/command/agent/auth"
	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/auth"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const orgIdFieldName = "org_id"

var (
	reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")
)

// Service handles request as described by the pbs.AuthMethodServiceServer interface.
type Service struct {
	repoFn func() (*iam.Repository, error)
}

// NewService returns a user service which handles user related requests to watchtower.
func NewService(repo func() (*iam.Repository, error)) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repoFn: repo}, nil
}

var _ pbs.AuthMethodServiceServer = Service{}

// ListAuthMethods implements the interface pbs.AuthMethodServiceServer.
func (s Service) ListAuthMethods(ctx context.Context, req *pbs.ListAuthMethodsRequest) (*pbs.ListAuthMethodsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	ul, err := s.listFromRepo(ctx, req.GetOrgId())
	if err != nil {
		return nil, err
	}
	return &pbs.ListAuthMethodsResponse{Items: ul}, nil
}

// GetAuthMethods implements the interface pbs.AuthMethodServiceServer.
func (s Service) GetAuthMethod(ctx context.Context, req *pbs.GetAuthMethodRequest) (*pbs.GetAuthMethodResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.GetAuthMethodResponse{Item: u}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.AuthMethod, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	u, err := repo.LookupAuthMethod(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist.", id)
		}
		return nil, err
	}
	if u == nil {
		return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist.", id)
	}
	return toProto(u), nil
}

func (s Service) listFromRepo(ctx context.Context, orgId string) ([]*pb.AuthMethod, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListAuthMethods(ctx, orgId)
	if err != nil {
		return nil, err
	}
	var outUl []*pb.AuthMethod
	for _, u := range ul {
		outUl = append(outUl, toProto(u))
	}
	return outUl, nil
}

func toProto(in *auth.AuthMethod) *pb.AuthMethod {
	out := pb.AuthMethod{
		Id:          in.GetPublicId(),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
	}
	if in.GetDescription() != "" {
		out.Description = &wrapperspb.StringValue{Value: in.GetDescription()}
	}
	if in.GetName() != "" {
		out.Name = &wrapperspb.StringValue{Value: in.GetName()}
	}
	return &out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetAuthMethodRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetId(), iam.AuthMethodPrefix+"_") {
		badFields["id"] = "Invalid formatted user id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateListRequest(req *pbs.ListAuthMethodsRequest) error {
	badFields := validateAncestors(req)
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
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

type ancestorProvider interface {
	GetOrgId() string
}

// validateAncestors verifies that the ancestors of this call are properly set and provided.
func validateAncestors(r ancestorProvider) map[string]string {
	if r.GetOrgId() == "" {
		return map[string]string{orgIdFieldName: "Missing organization id."}
	}
	if !validId(r.GetOrgId(), scope.Organization.Prefix()+"_") {
		return map[string]string{orgIdFieldName: "Improperly formatted identifier."}
	}
	return map[string]string{}
}
