package scopes

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/watchtower/internal/auth"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/scopes"
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
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	pl, err := s.listFromRepo(ctx, authResults.Scope.GetId())
	if err != nil {
		return nil, err
	}

	for _, item := range pl {
		item.Scope = authResults.Scope
	}

	return &pbs.ListScopesResponse{Items: pl}, nil
}

// GetScopes implements the interface pbs.ScopeServiceServer.
func (s Service) GetScope(ctx context.Context, req *pbs.GetScopeRequest) (*pbs.GetScopeResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	p, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	p.Scope = authResults.Scope
	return &pbs.GetScopeResponse{Item: p}, nil
}

// CreateScope implements the interface pbs.ScopeServiceServer.
func (s Service) CreateScope(ctx context.Context, req *pbs.CreateScopeRequest) (*pbs.CreateScopeResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	p, err := s.createInRepo(ctx, authResults.Scope, req.GetItem())
	if err != nil {
		return nil, err
	}
	p.Scope = authResults.Scope
	return &pbs.CreateScopeResponse{Item: p, Uri: fmt.Sprintf("scopes/%s", p.GetId())}, nil
}

// UpdateScope implements the interface pbs.ScopeServiceServer.
func (s Service) UpdateScope(ctx context.Context, req *pbs.UpdateScopeRequest) (*pbs.UpdateScopeResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	p, err := s.updateInRepo(ctx, authResults.Scope, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	p.Scope = authResults.Scope
	return &pbs.UpdateScopeResponse{Item: p}, nil
}

// DeleteScope implements the interface pbs.ScopeServiceServer.
func (s Service) DeleteScope(ctx context.Context, req *pbs.DeleteScopeRequest) (*pbs.DeleteScopeResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
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

func (s Service) createInRepo(ctx context.Context, parentScope *scopes.ScopeInfo, item *pb.Scope) (*pb.Scope, error) {
	var opts []iam.Option
	if item.GetName() != nil {
		opts = append(opts, iam.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, iam.WithDescription(item.GetDescription().GetValue()))
	}

	var iamScope *iam.Scope
	var err error
	switch parentScope.GetType() {
	case scope.Global.String():
		iamScope, err = iam.NewOrg(opts...)
	case scope.Org.String():
		iamScope, err = iam.NewProject(parentScope.GetId(), opts...)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build new scope for creation: %v.", err)
	}
	repo, err := s.repo()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateScope(ctx, iamScope)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create scope: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create scope but no error returned from repository.")
	}
	return toProto(out), nil
}

func (s Service) updateInRepo(ctx context.Context, parentScope *scopes.ScopeInfo, scopeId string, mask []string, item *pb.Scope) (*pb.Scope, error) {
	var opts []iam.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	var iamScope *iam.Scope
	var err error
	switch parentScope.GetType() {
	case scope.Global.String():
		iamScope, err = iam.NewOrg(opts...)
	case scope.Org.String():
		iamScope, err = iam.NewProject(parentScope.GetId(), opts...)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build scope for update: %v.", err)
	}
	iamScope.PublicId = scopeId
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
	out, rowsUpdated, err := repo.UpdateScope(ctx, iamScope, dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update project: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Scope %q doesn't exist.", scopeId)
	}
	return toProto(out), nil
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId string) (bool, error) {
	repo, err := s.repo()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteScope(ctx, scopeId)
	if err != nil {
		return false, status.Errorf(codes.Internal, "Unable to delete scope: %v.", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, scopeId string) ([]*pb.Scope, error) {
	repo, err := s.repo()
	if err != nil {
		return nil, err
	}

	var scps []*iam.Scope
	switch {
	case scopeId == "global":
		scps, err = repo.ListOrgs(ctx)
	case strings.HasPrefix(scopeId, scope.Org.Prefix()):
		scps, err = repo.ListProjects(ctx, scopeId)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "Invalid scope ID given for listing")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to list scopes: %v", err)
	}
	var outPl []*pb.Scope
	for _, p := range scps {
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
	badFields := map[string]string{}
	id := req.GetId()
	switch {
	case id == "global":
	case strings.HasPrefix(id, scope.Org.Prefix()):
		if !validId(id, scope.Org.Prefix()+"_") {
			badFields["id"] = "Invalidly formatted scope id."
		}
	case strings.HasPrefix(id, scope.Project.Prefix()):
		if !validId(id, scope.Project.Prefix()+"_") {
			badFields["id"] = "Invalidly formatted scope id."
		}
	default:
		badFields["id"] = "Invalidly formatted scope id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateCreateRequest(req *pbs.CreateScopeRequest) error {
	badFields := map[string]string{}
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
	badFields := map[string]string{}
	id := req.GetId()
	switch {
	case id == "global":
	case strings.HasPrefix(id, scope.Org.Prefix()):
		if !validId(id, scope.Org.Prefix()+"_") {
			badFields["id"] = "Invalidly formatted scope id."
		}
	case strings.HasPrefix(id, scope.Project.Prefix()):
		if !validId(id, scope.Project.Prefix()+"_") {
			badFields["id"] = "Invalidly formatted scope id."
		}
	default:
		badFields["id"] = "Invalidly formatted scope id."
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
	badFields := map[string]string{}
	id := req.GetId()
	switch {
	case id == "global":
	case strings.HasPrefix(id, scope.Org.Prefix()):
		if !validId(id, scope.Org.Prefix()+"_") {
			badFields["id"] = "Invalidly formatted scope id."
		}
	case strings.HasPrefix(id, scope.Project.Prefix()):
		if !validId(id, scope.Project.Prefix()+"_") {
			badFields["id"] = "Invalidly formatted scope id."
		}
	default:
		badFields["id"] = "Invalidly formatted scope id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateListRequest(req *pbs.ListScopesRequest) error {
	badFields := map[string]string{}
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
