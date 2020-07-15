package roles

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/roles"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/perms"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	orgIdFieldName  = "org_id"
	projIdFieldName = "project_id"
)

var (
	reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")
	// TODO(ICU-28): Find a way to auto update these names and enforce the mappings between wire and storage.
	wireToStorageMask = map[string]string{
		"name":           "Name",
		"description":    "Description",
		"grant_scope_id": "GrantScopeId",
	}
)

// Service handles request as described by the pbs.RoleServiceServer interface.
type Service struct {
	repoFn func() (*iam.Repository, error)
}

// NewService returns a role service which handles role related requests to watchtower.
func NewService(repo func() (*iam.Repository, error)) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repoFn: repo}, nil
}

var _ pbs.RoleServiceServer = Service{}

// ListRoles implements the interface pbs.RoleServiceServer.
func (s Service) ListRoles(ctx context.Context, req *pbs.ListRolesRequest) (*pbs.ListRolesResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	gl, err := s.listFromRepo(ctx, parentScope(req))
	if err != nil {
		return nil, err
	}
	return &pbs.ListRolesResponse{Items: gl}, nil
}

// GetRoles implements the interface pbs.RoleServiceServer.
func (s Service) GetRole(ctx context.Context, req *pbs.GetRoleRequest) (*pbs.GetRoleResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.GetRoleResponse{Item: u}, nil
}

// CreateRole implements the interface pbs.RoleServiceServer.
func (s Service) CreateRole(ctx context.Context, req *pbs.CreateRoleRequest) (*pbs.CreateRoleResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	r, err := s.createInRepo(ctx, parentScope(req), req.GetItem())
	if err != nil {
		return nil, err
	}
	return &pbs.CreateRoleResponse{Item: r, Uri: fmt.Sprintf("scopes/%s/roles/%s", req.GetScopeId(), r.GetId())}, nil
}

// UpdateRole implements the interface pbs.RoleServiceServer.
func (s Service) UpdateRole(ctx context.Context, req *pbs.UpdateRoleRequest) (*pbs.UpdateRoleResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	u, err := s.updateInRepo(ctx, parentScope(req), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	return &pbs.UpdateRoleResponse{Item: u}, nil
}

// DeleteRole implements the interface pbs.RoleServiceServer.
func (s Service) DeleteRole(ctx context.Context, req *pbs.DeleteRoleRequest) (*pbs.DeleteRoleResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	existed, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteRoleResponse{Existed: existed}, nil
}

// AddRolePrincipals implements the interface pbs.RoleServiceServer.
func (s Service) AddRolePrincipals(ctx context.Context, req *pbs.AddRolePrincipalsRequest) (*pbs.AddRolePrincipalsResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateAddRolePrincipalsRequest(req); err != nil {
		return nil, err
	}
	r, err := s.addPrinciplesInRepo(ctx, req.GetRoleId(), req.GetPrincipalIds(), req.GetVersion().GetValue())
	if err != nil {
		return nil, err
	}
	return &pbs.AddRolePrincipalsResponse{Item: r}, nil
}

// SetRolePrincipals implements the interface pbs.RoleServiceServer.
func (s Service) SetRolePrincipals(ctx context.Context, req *pbs.SetRolePrincipalsRequest) (*pbs.SetRolePrincipalsResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateSetRolePrincipalsRequest(req); err != nil {
		return nil, err
	}
	r, err := s.setPrinciplesInRepo(ctx, req.GetRoleId(), req.GetPrincipalIds(), req.GetVersion().GetValue())
	if err != nil {
		return nil, err
	}
	return &pbs.SetRolePrincipalsResponse{Item: r}, nil
}

// RemoveRolePrincipals implements the interface pbs.RoleServiceServer.
func (s Service) RemoveRolePrincipals(ctx context.Context, req *pbs.RemoveRolePrincipalsRequest) (*pbs.RemoveRolePrincipalsResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateRemoveRolePrincipalsRequest(req); err != nil {
		return nil, err
	}
	r, err := s.removePrinciplesInRepo(ctx, req.GetRoleId(), req.GetPrincipalIds(), req.GetVersion().GetValue())
	if err != nil {
		return nil, err
	}
	return &pbs.RemoveRolePrincipalsResponse{Item: r}, nil
}

// AddRoleGrants implements the interface pbs.RoleServiceServer.
func (s Service) AddRoleGrants(ctx context.Context, req *pbs.AddRoleGrantsRequest) (*pbs.AddRoleGrantsResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateAddRoleGrantsRequest(req); err != nil {
		return nil, err
	}
	r, err := s.addGrantsInRepo(ctx, req.GetRoleId(), req.GetGrants(), req.GetVersion().GetValue())
	if err != nil {
		return nil, err
	}
	return &pbs.AddRoleGrantsResponse{Item: r}, nil
}

// SetRoleGrants implements the interface pbs.RoleServiceServer.
func (s Service) SetRoleGrants(ctx context.Context, req *pbs.SetRoleGrantsRequest) (*pbs.SetRoleGrantsResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateSetRoleGrantsRequest(req); err != nil {
		return nil, err
	}
	r, err := s.setGrantsInRepo(ctx, req.GetRoleId(), req.GetGrants(), req.GetVersion().GetValue())
	if err != nil {
		return nil, err
	}
	return &pbs.SetRoleGrantsResponse{Item: r}, nil
}

// RemoveRoleGrants implements the interface pbs.RoleServiceServer.
func (s Service) RemoveRoleGrants(ctx context.Context, req *pbs.RemoveRoleGrantsRequest) (*pbs.RemoveRoleGrantsResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateRemoveRoleGrantsRequest(req); err != nil {
		return nil, err
	}
	r, err := s.removeGrantsInRepo(ctx, req.GetRoleId(), req.GetGrants(), req.GetVersion().GetValue())
	if err != nil {
		return nil, err
	}
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
		return nil, status.Errorf(codes.Internal, "Unable to build role for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateRole(ctx, u)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create role: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create role but no error returned from repository.")
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

	u, err := iam.NewRole(scopeId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build role for update: %v.", err)
	}
	u.PublicId = id
	dbMask, err := toDbUpdateMask(mask)
	if err != nil {
		return nil, err
	}
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid paths provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateRole(ctx, u, dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update role: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Role %q doesn't exist.", id)
	}
	// TODO: Attach principals and grants to UpdateRole response
	return toProto(out, nil, nil), nil
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
		return false, status.Errorf(codes.Internal, "Unable to delete role: %v.", err)
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
		return nil, status.Errorf(codes.Internal, "Unable to add principles to role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to look up role: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup role after adding principles to it.")
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
		return nil, status.Errorf(codes.Internal, "Unable to set principles on role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to look up role: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup role after setting principles for it.")
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
		return nil, status.Errorf(codes.Internal, "Unable to remove principles from role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to look up role: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup role after removing principles from it.")
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
		return nil, status.Errorf(codes.Internal, "Unable to add grants to role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, status.Error(codes.Internal, "Error looking up role after adding grants to it.")
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup role after adding grants to it.")
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
		return nil, status.Errorf(codes.Internal, "Unable to set grants on role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, status.Error(codes.Internal, "Error looking up role after setting grants on it.")
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup role after setting grants on it.")
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
		return nil, status.Errorf(codes.Internal, "Unable to remove grants from role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, status.Error(codes.Internal, "Error looking up role after removing grants from it.")
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup role after removing grants from it.")
	}
	return toProto(out, pr, roleGrants), nil
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

func toProto(in *iam.Role, principals []iam.PrincipalRole, grants []*iam.RoleGrant) *pb.Role {
	out := pb.Role{
		Id:          in.GetPublicId(),
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
		out.Grants = append(out.Grants, g.GetRawGrant())
		parsed, err := perms.Parse(in.GetGrantScopeId(), "", g.GetRawGrant())
		if err != nil {
			// This should never happen as we validate on the way in, but let's
			// return what we can since we are still returning the raw grant
			out.GrantsCanonical = append(out.GrantsCanonical, "<parse_error>")
			out.GrantsJson = append(out.GrantsJson, "<parse_error>")
		} else {
			out.GrantsCanonical = append(out.GrantsCanonical, parsed.CanonicalString())
			jsonGrant, err := parsed.MarshalJSON()
			if err != nil {
				// Again, this should never happen, but let's return what we
				// have anyways
				out.GrantsJson = append(out.GrantsJson, "<parse_error>")
			} else {
				out.GrantsJson = append(out.GrantsJson, string(jsonGrant))
			}
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
	badFields := validateAncestors(req)
	if !validId(req.GetId(), iam.RolePrefix+"_") {
		badFields["id"] = "Invalid formatted role id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateCreateRequest(req *pbs.CreateRoleRequest) error {
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
	if item.GetGrantScopeId() != nil && req.ProjectId != "" {
		if item.GetGrantScopeId().Value != req.ProjectId {
			badFields["grant_scope_id"] = "Must be empty or set to the project_id when the scope type is project."
		}
	}
	if item.GetPrincipals() != nil {
		badFields["principals"] = "This is a read only field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Argument errors found in the request.", badFields)
	}
	return nil
}

func validateUpdateRequest(req *pbs.UpdateRoleRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetId(), iam.RolePrefix+"_") {
		badFields["role_id"] = "Improperly formatted path identifier."
	}
	if req.GetUpdateMask() == nil {
		badFields["update_mask"] = "UpdateMask not provided but is required to update a role."
	}

	item := req.GetItem()
	if item == nil {
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
	if item.GetPrincipals() != nil {
		badFields["principals"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetGrantScopeId() != nil && req.ProjectId != "" {
		if item.GetGrantScopeId().Value != req.ProjectId {
			badFields["grant_scope_id"] = "Must be empty or set to the project_id when the scope type is project."
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}

	return nil
}

func validateDeleteRequest(req *pbs.DeleteRoleRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetId(), iam.RolePrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateListRequest(req *pbs.ListRolesRequest) error {
	badFields := validateAncestors(req)
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddRolePrincipalsRequest(req *pbs.AddRolePrincipalsRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetRoleId(), iam.RolePrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == nil {
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

func validateSetRolePrincipalsRequest(req *pbs.SetRolePrincipalsRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetRoleId(), iam.RolePrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == nil {
		badFields["version"] = "Required field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveRolePrincipalsRequest(req *pbs.RemoveRolePrincipalsRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetRoleId(), iam.RolePrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == nil {
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
	badFields := validateAncestors(req)
	if !validId(req.GetRoleId(), iam.RolePrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == nil {
		badFields["version"] = "Required field."
	}
	if len(req.GetGrants()) == 0 {
		badFields["grants"] = "Must be non-empty."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetRoleGrantsRequest(req *pbs.SetRoleGrantsRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetRoleId(), iam.RolePrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == nil {
		badFields["version"] = "Required field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveRoleGrantsRequest(req *pbs.RemoveRoleGrantsRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetRoleId(), iam.RolePrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == nil {
		badFields["version"] = "Required field."
	}
	if len(req.GetGrants()) == 0 {
		badFields["grants"] = "Must be non-empty."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
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
	GetScopeId() string
}

// validateAncestors verifies that the ancestors of this call are properly set and provided.
func validateAncestors(r ancestorProvider) map[string]string {
	if r.GetScopeId() == "" {
		return map[string]string{orgIdFieldName: "Missing org id."}
	}
	if !validId(r.GetScopeId(), scope.Org.Prefix()+"_") {
		return map[string]string{orgIdFieldName: "Improperly formatted identifier."}
	}
	return map[string]string{}
}

// Given an ancestorProvider, return the resource's immediate parent scope
func parentScope(r ancestorProvider) string {
	return r.GetScopeId()
}
