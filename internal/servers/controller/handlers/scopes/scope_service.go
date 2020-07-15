package projects

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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")
	// TODO(ICU-28): Find a way to auto update these names and enforce the mappings between wire and storage.
	wireToStorageMask = map[string]string{
		"name":        "Name",
		"description": "Description",
	}
)

// Service handles request as described by the pbs.ScopeServiceServer interface.
type Service struct {
	repo common.IamRepoFactory
}

// NewService returns a project service which handles project related requests to watchtower.
func NewService(repo common.IamRepoFactory) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repo: repo}, nil
}

var _ pbs.ScopeServiceServer = Service{}

// ListScopes implements the interface pbs.ScopeServiceServer.
func (s Service) ListScopes(ctx context.Context, req *pbs.ListScopesRequest) (*pbs.ListScopesResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	pl, err := s.listFromRepo(ctx, "global")
	if err != nil {
		return nil, err
	}
	return &pbs.ListScopesResponse{Items: pl}, nil
}

// GetScopes implements the interface pbs.ScopeServiceServer.
func (s Service) GetScope(ctx context.Context, req *pbs.GetScopeRequest) (*pbs.GetScopeResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	p, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.GetScopeResponse{Item: p}, nil
}

// CreateScope implements the interface pbs.ScopeServiceServer.
func (s Service) CreateScope(ctx context.Context, req *pbs.CreateScopeRequest) (*pbs.CreateScopeResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	p, err := s.createInRepo(ctx, "global", req.GetItem())
	if err != nil {
		return nil, err
	}
	return &pbs.CreateScopeResponse{Item: p, Uri: fmt.Sprintf("scopes/%s", p.GetId())}, nil
}

// UpdateScope implements the interface pbs.ScopeServiceServer.
func (s Service) UpdateScope(ctx context.Context, req *pbs.UpdateScopeRequest) (*pbs.UpdateScopeResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	p, err := s.updateInRepo(ctx, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	return &pbs.UpdateScopeResponse{Item: p}, nil
}

// DeleteScope implements the interface pbs.ScopeServiceServer.
func (s Service) DeleteScope(ctx context.Context, req *pbs.DeleteScopeRequest) (*pbs.DeleteScopeResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	existed, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteScopeResponse{Existed: existed}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Scope, error) {
	repo, err := s.repo()
	if err != nil {
		return nil, err
	}
	p, err := repo.LookupScope(ctx, id)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, handlers.NotFoundErrorf("Scope %q doesn't exist.", id)
	}
	return toProto(p), nil
}

func (s Service) createInRepo(ctx context.Context, orgID string, item *pb.Scope) (*pb.Scope, error) {
	var opts []iam.Option
	if item.GetName() != nil {
		opts = append(opts, iam.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, iam.WithDescription(item.GetDescription().GetValue()))
	}
	p, err := iam.NewScope(orgID, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build project for creation: %v.", err)
	}
	repo, err := s.repo()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateScope(ctx, p)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create project: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create project but no error returned from repository.")
	}
	return toProto(out), nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId string, mask []string, item *pb.Scope) (*pb.Scope, error) {
	var opts []iam.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	p, err := iam.NewScope(scopeId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build project for update: %v.", err)
	}
	p.PublicId = scopeId
	dbMask, err := toDbUpdateMask(mask)
	if err != nil {
		return nil, err
	}
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid paths provided in the update mask."})
	}
	repo, err := s.repo()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateScope(ctx, p, dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update project: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Scope %q doesn't exist.", scopeId)
	}
	return toProto(out), nil
}

func (s Service) deleteFromRepo(ctx context.Context, projId string) (bool, error) {
	repo, err := s.repo()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteScope(ctx, projId)
	if err != nil {
		return false, status.Errorf(codes.Internal, "Unable to delete project: %v.", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, orgId string) ([]*pb.Scope, error) {
	repo, err := s.repo()
	if err != nil {
		return nil, err
	}
	pl, err := repo.ListScopes(ctx, "global")
	if err != nil {
		return nil, err
	}
	var outPl []*pb.Scope
	for _, p := range pl {
		outPl = append(outPl, toProto(p))
	}
	return outPl, nil
}

// toDbUpdateMask converts the wire format's FieldMask into a list of strings containing FieldMask paths used
func toDbUpdateMask(paths []string) ([]string, error) {
	var dbPaths []string
	var invalid []string
	for _, p := range paths {
		for _, f := range strings.Split(p, ",") {
			if dbField, ok := wireToStorageMask[strings.TrimSpace(f)]; ok {
				dbPaths = append(dbPaths, dbField)
			} else {
				invalid = append(invalid, f)
			}
		}
	}
	if len(invalid) > 0 {
		return nil, handlers.InvalidArgumentErrorf(fmt.Sprintf("Invalid fields passed in update_update mask: %v.", invalid), map[string]string{"update_mask": fmt.Sprintf("Unknown paths provided in update mask: %q", strings.Join(invalid, ","))})
	}
	return dbPaths, nil
}

func toProto(in *iam.Scope) *pb.Scope {
	out := pb.Scope{
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
func validateGetRequest(req *pbs.GetScopeRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetId(), scope.Scope.Prefix()+"_") {
		badFields["id"] = "Invalid formatted project id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateCreateRequest(req *pbs.CreateScopeRequest) error {
	badFields := validateAncestors(req)
	item := req.GetItem()
	if item.GetId() != "" {
		badFields["id"] = "This is a read only field."
	}
	if item.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field."
	}
	if item.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This is a read only field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Argument errors found in the request.", badFields)
	}
	return nil
}

func validateUpdateRequest(req *pbs.UpdateScopeRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetId(), scope.Scope.Prefix()+"_") {
		badFields["project_id"] = "Improperly formatted path identifier."
	}
	if req.GetUpdateMask() == nil {
		badFields["update_mask"] = "UpdateMask not provided but is required to update a project."
	}

	item := req.GetItem()
	if item == nil {
		if len(badFields) > 0 {
			return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
		}
		// It is legitimate for no item to be specified in an update request as it indicates all fields provided in
		// the mask will be marked as unset.
		return nil
	}
	if item.GetId() != "" {
		badFields["id"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This is a read only field and cannot be specified in an update request."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}

	return nil
}

func validateDeleteRequest(req *pbs.DeleteScopeRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetId(), scope.Scope.Prefix()+"_") {
		badFields["id"] = "Incorrectly formatted project."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateListRequest(req *pbs.ListScopesRequest) error {
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
		return map[string]string{orgIdFieldName: "Missing org id."}
	}
	if !validId(r.GetOrgId(), scope.Org.Prefix()+"_") {
		return map[string]string{orgIdFieldName: "Improperly formatted identifier."}
	}
	return map[string]string{}
}
