package orgs

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

// Service handles request as described by the pbs.OrgServiceServer interface.
type Service struct {
	repo common.IamRepoFactory
}

// NewService returns an org service which handles org related requests to watchtower.
func NewService(repo common.IamRepoFactory) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repo: repo}, nil
}

var _ pbs.OrgServiceServer = Service{}

// ListOrgs is not yet implemented but will implement the interface pbs.OrgServiceServer.
func (s Service) ListOrgs(ctx context.Context, req *pbs.ListOrgsRequest) (*pbs.ListOrgsResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	ol, err := s.listFromRepo(ctx)
	if err != nil {
		return nil, err
	}
	return &pbs.ListOrgsResponse{Items: ol}, nil
}

// GetOrgs implements the interface pbs.OrgServiceServer.
func (s Service) GetOrg(ctx context.Context, req *pbs.GetOrgRequest) (*pbs.GetOrgResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	o, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.GetOrgResponse{Item: o}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Org, error) {
	repo, err := s.repo()
	if err != nil {
		return nil, err
	}
	p, err := repo.LookupScope(ctx, id)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, handlers.NotFoundErrorf("Org %q doesn't exist.", id)
	}
	return toProto(p), nil
}

func (s Service) listFromRepo(ctx context.Context) ([]*pb.Org, error) {
	repo, err := s.repo()
	if err != nil {
		return nil, err
	}
	ol, err := repo.ListOrgs(ctx)
	if err != nil {
		return nil, err
	}
	var outOl []*pb.Org
	for _, o := range ol {
		outOl = append(outOl, toProto(o))
	}
	return outOl, nil
}

func toProto(in *iam.Scope) *pb.Org {
	out := pb.Org{
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
func validateGetRequest(req *pbs.GetOrgRequest) error {
	badFields := make(map[string]string)
	if !validId(req.GetId(), scope.Org.Prefix()+"_") {
		badFields["id"] = "Invalid formatted org id."
	}
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
