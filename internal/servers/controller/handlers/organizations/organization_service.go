package organizations

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/common"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const orgIdFieldName = "org_id"

var (
	reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")
)

// Service handles request as described by the pbs.OrganizationServiceServer interface.
type Service struct {
	iamRepo common.IamRepoFactory
}

// NewService returns an organization service which handles organization related requests to watchtower.
func NewService(iamRepo common.IamRepoFactory) (Service, error) {
	if iamRepo == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{iamRepo: iamRepo}, nil
}

var _ pbs.OrganizationServiceServer = Service{}

// ListOrganizations is not yet implemented but will implement the interface pbs.OrganizationServiceServer.
func (s Service) ListOrganizations(ctx context.Context, req *pbs.ListOrganizationsRequest) (*pbs.ListOrganizationsResponse, error) {
	ol, err := s.listFromRepo(ctx)
	if err != nil {
		return nil, err
	}
	return &pbs.ListOrganizationsResponse{Items: ol}, nil
}

// GetOrganizations implements the interface pbs.OrganizationServiceServer.
func (s Service) GetOrganization(ctx context.Context, req *pbs.GetOrganizationRequest) (*pbs.GetOrganizationResponse, error) {
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	o, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.GetOrganizationResponse{Item: o}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Organization, error) {
	repo, err := s.iamRepo()
	if err != nil {
		return nil, err
	}
	p, err := repo.LookupScope(ctx, id)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, handlers.NotFoundErrorf("Organization %q doesn't exist.", id)
	}
	return toProto(p), nil
}

func (s Service) listFromRepo(ctx context.Context) ([]*pb.Organization, error) {
	repo, err := s.iamRepo()
	if err != nil {
		return nil, err
	}
	ol, err := repo.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	var outOl []*pb.Organization
	for _, o := range ol {
		outOl = append(outOl, toProto(o))
	}
	return outOl, nil
}

func toProto(in *iam.Scope) *pb.Organization {
	out := pb.Organization{
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
func validateGetRequest(req *pbs.GetOrganizationRequest) error {
	badFields := make(map[string]string)
	if !validId(req.GetId(), scope.Organization.Prefix()+"_") {
		badFields["id"] = "Invalid formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

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
	if req.GetPasswordCredential() == nil {
		badFields["password_credential"] = "This is a required field."
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
