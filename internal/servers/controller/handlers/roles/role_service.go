package roles

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/roles"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.Role{}, &pb.Role{}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.RoleServiceServer interface.
type Service struct {
	repoFn common.IamRepoFactory
}

// NewService returns a role service which handles role related requests to boundary.
func NewService(repo common.IamRepoFactory) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repoFn: repo}, nil
}

var _ pbs.RoleServiceServer = Service{}

// ListRoles implements the interface pbs.RoleServiceServer.
func (s Service) ListRoles(ctx context.Context, req *pbs.ListRolesRequest) (*pbs.ListRolesResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	gl, err := s.listFromRepo(ctx, req.GetScopeId())
	if err != nil {
		return nil, err
	}
	for _, item := range gl {
		item.Scope = authResults.Scope
	}
	return &pbs.ListRolesResponse{Items: gl}, nil
}

// GetRoles implements the interface pbs.RoleServiceServer.
func (s Service) GetRole(ctx context.Context, req *pbs.GetRoleRequest) (*pbs.GetRoleResponse, error) {
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.GetRoleResponse{Item: u}, nil
}

// CreateRole implements the interface pbs.RoleServiceServer.
func (s Service) CreateRole(ctx context.Context, req *pbs.CreateRoleRequest) (*pbs.CreateRoleResponse, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	r.Scope = authResults.Scope
	return &pbs.CreateRoleResponse{Item: r, Uri: fmt.Sprintf("roles/%s", r.GetId())}, nil
}

// UpdateRole implements the interface pbs.RoleServiceServer.
func (s Service) UpdateRole(ctx context.Context, req *pbs.UpdateRoleRequest) (*pbs.UpdateRoleResponse, error) {
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.UpdateRoleResponse{Item: u}, nil
}

// DeleteRole implements the interface pbs.RoleServiceServer.
func (s Service) DeleteRole(ctx context.Context, req *pbs.DeleteRoleRequest) (*pbs.DeleteRoleResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Delete)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	_, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteRoleResponse{}, nil
}

// AddRolePrincipals implements the interface pbs.RoleServiceServer.
func (s Service) AddRolePrincipals(ctx context.Context, req *pbs.AddRolePrincipalsRequest) (*pbs.AddRolePrincipalsResponse, error) {
	if err := validateAddRolePrincipalsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddPrincipals)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, err := s.addPrinciplesInRepo(ctx, req.GetId(), req.GetPrincipalIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	r.Scope = authResults.Scope
	return &pbs.AddRolePrincipalsResponse{Item: r}, nil
}

// SetRolePrincipals implements the interface pbs.RoleServiceServer.
func (s Service) SetRolePrincipals(ctx context.Context, req *pbs.SetRolePrincipalsRequest) (*pbs.SetRolePrincipalsResponse, error) {
	if err := validateSetRolePrincipalsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetPrincipals)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, err := s.setPrinciplesInRepo(ctx, req.GetId(), req.GetPrincipalIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	r.Scope = authResults.Scope
	return &pbs.SetRolePrincipalsResponse{Item: r}, nil
}

// RemoveRolePrincipals implements the interface pbs.RoleServiceServer.
func (s Service) RemoveRolePrincipals(ctx context.Context, req *pbs.RemoveRolePrincipalsRequest) (*pbs.RemoveRolePrincipalsResponse, error) {
	if err := validateRemoveRolePrincipalsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemovePrincipals)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, err := s.removePrinciplesInRepo(ctx, req.GetId(), req.GetPrincipalIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	r.Scope = authResults.Scope
	return &pbs.RemoveRolePrincipalsResponse{Item: r}, nil
}

// AddRoleGrants implements the interface pbs.RoleServiceServer.
func (s Service) AddRoleGrants(ctx context.Context, req *pbs.AddRoleGrantsRequest) (*pbs.AddRoleGrantsResponse, error) {
	if err := validateAddRoleGrantsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddGrants)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, err := s.addGrantsInRepo(ctx, req.GetId(), req.GetGrantStrings(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	r.Scope = authResults.Scope
	return &pbs.AddRoleGrantsResponse{Item: r}, nil
}

// SetRoleGrants implements the interface pbs.RoleServiceServer.
func (s Service) SetRoleGrants(ctx context.Context, req *pbs.SetRoleGrantsRequest) (*pbs.SetRoleGrantsResponse, error) {
	if err := validateSetRoleGrantsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetGrants)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, err := s.setGrantsInRepo(ctx, req.GetId(), req.GetGrantStrings(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	r.Scope = authResults.Scope
	return &pbs.SetRoleGrantsResponse{Item: r}, nil
}

// RemoveRoleGrants implements the interface pbs.RoleServiceServer.
func (s Service) RemoveRoleGrants(ctx context.Context, req *pbs.RemoveRoleGrantsRequest) (*pbs.RemoveRoleGrantsResponse, error) {
	if err := validateRemoveRoleGrantsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveGrants)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, err := s.removeGrantsInRepo(ctx, req.GetId(), req.GetGrantStrings(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	r.Scope = authResults.Scope
	return &pbs.RemoveRoleGrantsResponse{Item: r}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Role, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("Role %q doesn't exist.", id)
		}
		return nil, err
	}
	if out == nil {
		return nil, handlers.NotFoundErrorf("Role %q doesn't exist.", id)
	}
	return toProto(out, pr, roleGrants), nil
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.Role) (*pb.Role, error) {
	var opts []iam.Option
	if item.GetName() != nil {
		opts = append(opts, iam.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, iam.WithDescription(item.GetDescription().GetValue()))
	}
	if item.GetGrantScopeId() != nil {
		opts = append(opts, iam.WithGrantScopeId(item.GetGrantScopeId().GetValue()))
	}
	u, err := iam.NewRole(scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build role for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateRole(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("unable to create role: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create role but no error returned from repository.")
	}
	return toProto(out, nil, nil), nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Role) (*pb.Role, error) {
	var opts []iam.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	if grantScopeId := item.GetGrantScopeId(); grantScopeId != nil {
		opts = append(opts, iam.WithGrantScopeId(grantScopeId.GetValue()))
	}
	version := item.GetVersion()

	u, err := iam.NewRole(scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build role for update: %v.", err)
	}
	u.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, pr, gr, rowsUpdated, err := repo.UpdateRole(ctx, u, version, dbMask)
	if err != nil {
		return nil, fmt.Errorf("unable to update role: %w", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Role %q doesn't exist or incorrect version provided.", id)
	}
	return toProto(out, pr, gr), nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteRole(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("unable to delete role: %w", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, scopeId string) ([]*pb.Role, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	rl, err := repo.ListRoles(ctx, scopeId)
	if err != nil {
		return nil, err
	}
	var outRl []*pb.Role
	for _, g := range rl {
		// TODO: Attach principals and grants to ListRoles response.
		outRl = append(outRl, toProto(g, nil, nil))
	}
	return outRl, nil
}

func (s Service) addPrinciplesInRepo(ctx context.Context, roleId string, principalIds []string, version uint32) (*pb.Role, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.AddPrincipalRoles(ctx, roleId, version, principalIds)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add principals to role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up role after adding principals: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after adding principals to it.")
	}
	return toProto(out, pr, roleGrants), nil
}

func (s Service) setPrinciplesInRepo(ctx context.Context, roleId string, principalIds []string, version uint32) (*pb.Role, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, _, err = repo.SetPrincipalRoles(ctx, roleId, version, principalIds)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set principals on role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up role after setting principals: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after setting principals for it.")
	}
	return toProto(out, pr, roleGrants), nil
}

func (s Service) removePrinciplesInRepo(ctx context.Context, roleId string, principalIds []string, version uint32) (*pb.Role, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.DeletePrincipalRoles(ctx, roleId, version, principalIds)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove principals from role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up role after removing principals: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after removing principals from it.")
	}
	return toProto(out, pr, roleGrants), nil
}

func (s Service) addGrantsInRepo(ctx context.Context, roleId string, grants []string, version uint32) (*pb.Role, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.AddRoleGrants(ctx, roleId, version, grants)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add grants to role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up role after adding grants: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after adding grants to it.")
	}
	return toProto(out, pr, roleGrants), nil
}

func (s Service) setGrantsInRepo(ctx context.Context, roleId string, grants []string, version uint32) (*pb.Role, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	// If no grant was provided, we clear the grants.
	if grants == nil {
		grants = []string{}
	}
	_, _, err = repo.SetRoleGrants(ctx, roleId, version, grants)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set grants on role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up role after setting grants: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after setting grants on it.")
	}
	return toProto(out, pr, roleGrants), nil
}

func (s Service) removeGrantsInRepo(ctx context.Context, roleId string, grants []string, version uint32) (*pb.Role, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.DeleteRoleGrants(ctx, roleId, version, grants)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove grants from role: %v", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up role after removing grants: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after removing grants from it.")
	}
	return toProto(out, pr, roleGrants), nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.Role), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
		scp, err := repo.LookupScope(ctx, parentId)
		if err != nil {
			res.Error = err
			return res
		}
		if scp == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
	default:
		r, _, _, err := repo.LookupRole(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if r == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = r.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, opts...)
}

func toProto(in *iam.Role, principals []iam.PrincipalRole, grants []*iam.RoleGrant) *pb.Role {
	out := pb.Role{
		Id:          in.GetPublicId(),
		ScopeId:     in.GetScopeId(),
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
	for _, p := range principals {
		principal := &pb.Principal{
			Id:      p.GetPrincipalId(),
			Type:    p.GetType(),
			ScopeId: p.GetPrincipalScopeId(),
		}
		out.Principals = append(out.Principals, principal)
		out.PrincipalIds = append(out.PrincipalIds, p.GetPrincipalId())
	}
	for _, g := range grants {
		out.GrantStrings = append(out.GrantStrings, g.GetRawGrant())
		parsed, err := perms.Parse(in.GetGrantScopeId(), "", g.GetRawGrant())
		if err != nil {
			// This should never happen as we validate on the way in, but let's
			// return what we can since we are still returning the raw grant
			out.Grants = append(out.Grants, &pb.Grant{
				Raw:       g.GetRawGrant(),
				Canonical: "<parse_error>",
				Json:      nil,
			})
		} else {
			_, actions := parsed.Actions()
			out.Grants = append(out.Grants, &pb.Grant{
				Raw:       g.GetRawGrant(),
				Canonical: g.GetCanonicalGrant(),
				Json: &pb.GrantJson{
					Id:      parsed.Id(),
					Type:    parsed.Type().String(),
					Actions: actions,
				},
			})
		}
	}
	if in.GetGrantScopeId() != "" {
		out.GrantScopeId = &wrapperspb.StringValue{Value: in.GetGrantScopeId()}
	}
	return &out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetRoleRequest) error {
	return handlers.ValidateGetRequest(iam.RolePrefix, req, handlers.NoopValidatorFn)
}

func validateCreateRequest(req *pbs.CreateRoleRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		item := req.GetItem()
		if !handlers.ValidId(scope.Org.Prefix(), item.GetScopeId()) &&
			!handlers.ValidId(scope.Project.Prefix(), item.GetScopeId()) &&
			scope.Global.String() != item.GetScopeId() {
			badFields["scope_id"] = "This field is missing or improperly formatted."
		}
		if item.GetGrantScopeId() != nil && handlers.ValidId(scope.Project.Prefix(), item.GetScopeId()) {
			if item.GetGrantScopeId().GetValue() != item.GetScopeId() {
				badFields["grant_scope_id"] = "Must be empty or set to the project_id when the scope type is project."
			}
		}
		if item.GetPrincipals() != nil {
			badFields["principals"] = "This is a read only field."
		}
		if item.GetGrants() != nil {
			badFields["grant_strings"] = "This is a read only field."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateRoleRequest) error {
	return handlers.ValidateUpdateRequest(iam.RolePrefix, req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetPrincipalIds() != nil {
			badFields["principal_ids"] = "This is a read only field and cannot be specified in an update request."
		}
		if req.GetItem().GetPrincipals() != nil {
			badFields["principals"] = "This is a read only field and cannot be specified in an update request."
		}
		if req.GetItem().GetGrants() != nil {
			badFields["grants"] = "This is a read only field and cannot be specified in an update request."
		}
		if req.GetItem().GetGrantStrings() != nil {
			badFields["grant_strings"] = "This is a read only field and cannot be specified in an update request."
		}
		if req.GetItem().GetGrantScopeId() != nil && handlers.ValidId(scope.Project.Prefix(), req.GetItem().GetScopeId()) {
			if req.GetItem().GetGrantScopeId().GetValue() != req.GetItem().GetScopeId() {
				badFields["grant_scope_id"] = "Must be empty or set to the project_id when the scope type is project."
			}
		}
		return badFields
	})
}

func validateDeleteRequest(req *pbs.DeleteRoleRequest) error {
	return handlers.ValidateDeleteRequest(iam.RolePrefix, req, func() map[string]string {
		if req.GetId() == "r_default" {
			return map[string]string{
				"id": `Deleting "r_default" is not allowed`,
			}
		}
		return nil
	})
}

func validateListRequest(req *pbs.ListRolesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(scope.Org.Prefix(), req.GetScopeId()) &&
		!handlers.ValidId(scope.Project.Prefix(), req.GetScopeId()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "Improperly formatted field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddRolePrincipalsRequest(req *pbs.AddRolePrincipalsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(iam.RolePrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetPrincipalIds()) == 0 {
		badFields["principal_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetPrincipalIds() {
		if id == "u_recovery" {
			badFields["principal_ids"] = "u_recovery cannot be assigned to a role"
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetRolePrincipalsRequest(req *pbs.SetRolePrincipalsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(iam.RolePrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	for _, id := range req.GetPrincipalIds() {
		if id == "u_recovery" {
			badFields["principal_ids"] = "u_recovery cannot be assigned to a role"
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveRolePrincipalsRequest(req *pbs.RemoveRolePrincipalsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(iam.RolePrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetPrincipalIds()) == 0 {
		badFields["principal_ids"] = "Must be non-empty."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateAddRoleGrantsRequest(req *pbs.AddRoleGrantsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(iam.RolePrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetGrantStrings()) == 0 {
		badFields["grant_strings"] = "Must be non-empty."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetRoleGrantsRequest(req *pbs.SetRoleGrantsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(iam.RolePrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveRoleGrantsRequest(req *pbs.RemoveRoleGrantsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(iam.RolePrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetGrantStrings()) == 0 {
		badFields["grant_strings"] = "Must be non-empty."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
