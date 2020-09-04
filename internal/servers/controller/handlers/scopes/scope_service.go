package scopes

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.Scope{}, &pb.Scope{}); err != nil {
		panic(err)
	}
}

// Service handles requests as described by the pbs.ScopeServiceServer interface.
type Service struct {
	repoFn common.IamRepoFactory
}

// NewService returns a project service which handles project related requests to boundary.
func NewService(repo common.IamRepoFactory) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repoFn: repo}, nil
}

var _ pbs.ScopeServiceServer = Service{}

// ListScopes implements the interface pbs.ScopeServiceServer.
func (s Service) ListScopes(ctx context.Context, req *pbs.ListScopesRequest) (*pbs.ListScopesResponse, error) {
	if req.GetScopeId() == "" {
		req.ScopeId = scope.Global.String()
	}
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.pinAndAuthResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
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
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.pinAndAuthResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
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
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.pinAndAuthResult(ctx, req.GetItem().GetScopeId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	p, err := s.createInRepo(ctx, authResults, req)
	if err != nil {
		return nil, err
	}
	p.Scope = authResults.Scope
	return &pbs.CreateScopeResponse{Item: p, Uri: fmt.Sprintf("scopes/%s", p.GetId())}, nil
}

// UpdateScope implements the interface pbs.ScopeServiceServer.
func (s Service) UpdateScope(ctx context.Context, req *pbs.UpdateScopeRequest) (*pbs.UpdateScopeResponse, error) {
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.pinAndAuthResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
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
	return &pbs.DeleteScopeResponse{Existed: existed}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Scope, error) {
	repo, err := s.repoFn()
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
	return ToProto(p), nil
}

func (s Service) createInRepo(ctx context.Context, authResults auth.VerifyResults, req *pbs.CreateScopeRequest) (*pb.Scope, error) {
	item := req.GetItem()
	var opts []iam.Option
	if item.GetName() != nil {
		opts = append(opts, iam.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, iam.WithDescription(item.GetDescription().GetValue()))
	}
	opts = append(opts, iam.WithSkipRoleCreation(req.GetSkipRoleCreation()))

	parentScope := authResults.Scope
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
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateScope(ctx, iamScope, authResults.UserId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create scope: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create scope but no error returned from repository.")
	}
	return ToProto(out), nil
}

func (s Service) updateInRepo(ctx context.Context, parentScope *scopes.ScopeInfo, scopeId string, mask []string, item *pb.Scope) (*pb.Scope, error) {
	var opts []iam.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	version := item.GetVersion()

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
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateScope(ctx, iamScope, version, dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update project: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Scope %q doesn't exist.", scopeId)
	}
	return ToProto(out), nil
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId string) (bool, error) {
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteScope(ctx, scopeId)
	if err != nil {
		return false, status.Errorf(codes.Internal, "Unable to delete scope: %v.", err)
	}
	return rows > 0, nil
}

func SortScopes(scps []*pb.Scope) {
	// We stable sort here even though the database may not return things in
	// sorted order, still nice to have them as consistent as possible.
	sort.SliceStable(scps, func(i, j int) bool {
		return scps[i].GetId() < scps[j].GetId()
	})
}

func (s Service) listFromRepo(ctx context.Context, scopeId string) ([]*pb.Scope, error) {
	repo, err := s.repoFn()
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
	for _, scp := range scps {
		outPl = append(outPl, ToProto(scp))
	}
	SortScopes(outPl)
	return outPl, nil
}

func (s Service) pinAndAuthResult(ctx context.Context, id string, a action.Type) (*iam.Scope, auth.VerifyResults) {
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}

	var scp *iam.Scope
	opts := []auth.Option{auth.WithType(resource.Scope), auth.WithAction(a)}
	switch a {
	case action.List:
		fallthrough
	case action.Create:
		scp, err = repo.LookupScope(ctx, id)
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
		s, err := repo.LookupScope(ctx, id)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if s == nil {
			res.Error = handlers.ForbiddenError()
			return nil, res
		}
		opts = append(opts, auth.WithId(id), auth.WithScopeId(s.GetParentId()))
	}
	authResults := auth.Verify(ctx, opts...)
	return scp, authResults
}

func ToProto(in *iam.Scope) *pb.Scope {
	out := pb.Scope{
		Id:          in.GetPublicId(),
		ScopeId:     in.GetParentId(),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
		Version:     in.GetVersion(),
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
		if !handlers.ValidId(scope.Org.Prefix(), id) {
			badFields["id"] = "Invalidly formatted scope id."
		}
	case strings.HasPrefix(id, scope.Project.Prefix()):
		if !handlers.ValidId(scope.Project.Prefix(), id) {
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
	if item.GetScopeId() == "" {
		badFields["scope_id"] = "Missing value for scope_id"
	}
	if item.GetId() != "" {
		badFields["id"] = "This is a read only field."
	}
	if item.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field."
	}
	if item.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This is a read only field."
	}
	if item.GetVersion() != 0 {
		badFields["version"] = "This cannot be specified at create time."
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
		if !handlers.ValidId(scope.Org.Prefix(), id) {
			badFields["id"] = "Invalidly formatted scope id."
		}
	case strings.HasPrefix(id, scope.Project.Prefix()):
		if !handlers.ValidId(scope.Project.Prefix(), id) {
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
	if item.GetVersion() == 0 {
		badFields["version"] = "Existing resource version is required for an update."
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
		badFields["id"] = "Invalid to delete the global scope."
	case strings.HasPrefix(id, scope.Org.Prefix()):
		if !handlers.ValidId(scope.Org.Prefix(), id) {
			badFields["id"] = "Invalidly formatted scope id."
		}
	case strings.HasPrefix(id, scope.Project.Prefix()):
		if !handlers.ValidId(scope.Project.Prefix(), id) {
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
