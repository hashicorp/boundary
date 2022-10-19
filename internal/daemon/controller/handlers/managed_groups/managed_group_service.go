package managed_groups

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	oidcstore "github.com/hashicorp/boundary/internal/auth/oidc/store"
	requestauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/intglobals"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/managedgroups"
	"github.com/hashicorp/go-bexpr"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// oidc field names
	attrFilterField = "attributes.filter"

	domain = "auth"
)

var (
	oidcMaskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = map[subtypes.Subtype]action.ActionSet{
		oidc.Subtype: {
			action.NoOp,
			action.Read,
			action.Update,
			action.Delete,
		},
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.ActionSet{
		action.Create,
		action.List,
	}
)

func init() {
	var err error
	if oidcMaskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&oidcstore.ManagedGroup{}}, handlers.MaskSource{&pb.ManagedGroup{}, &pb.OidcManagedGroupAttributes{}}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.ManagedGroupServiceServer interface.
type Service struct {
	pbs.UnsafeManagedGroupServiceServer

	oidcRepoFn common.OidcAuthRepoFactory
}

var _ pbs.ManagedGroupServiceServer = (*Service)(nil)

// NewService returns a managed group service which handles managed group related requests to boundary.
func NewService(oidcRepo common.OidcAuthRepoFactory) (Service, error) {
	const op = "managed_groups.NewService"
	if oidcRepo == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing oidc repository provided")
	}
	return Service{oidcRepoFn: oidcRepo}, nil
}

// ListManagedGroups implements the interface pbs.ManagedGroupsServiceServer.
func (s Service) ListManagedGroups(ctx context.Context, req *pbs.ListManagedGroupsRequest) (*pbs.ListManagedGroupsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetAuthMethodId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	ul, err := s.listFromRepo(ctx, req.GetAuthMethodId())
	if err != nil {
		return nil, err
	}
	if len(ul) == 0 {
		return &pbs.ListManagedGroupsResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.ManagedGroup, 0, len(ul))

	res := perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.ManagedGroup,
		Pin:     req.GetAuthMethodId(),
	}
	for _, mg := range ul {
		res.Id = mg.GetPublicId()
		authorizedActions := authResults.FetchActionSetForId(ctx, mg.GetPublicId(), IdActions[subtypes.SubtypeFromId(domain, mg.GetPublicId())], requestauth.WithResource(&res)).Strings()
		if len(authorizedActions) == 0 {
			continue
		}

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserData.User.Id)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
		}

		item, err := toProto(ctx, mg, outputOpts...)
		if err != nil {
			return nil, err
		}

		// This comes last so that we can use item fields in the filter after
		// the allowed fields are populated above
		filterable, err := subtypes.Filterable(item)
		if err != nil {
			return nil, err
		}
		if filter.Match(filterable) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListManagedGroupsResponse{Items: finalItems}, nil
}

// GetManagedGroup implements the interface pbs.ManagedGroupServiceServer.
func (s Service) GetManagedGroup(ctx context.Context, req *pbs.GetManagedGroupRequest) (*pbs.GetManagedGroupResponse, error) {
	const op = "managed_groups.(Service).GetManagedGroup"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}

	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	mg, memberIds, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, mg.GetPublicId(), IdActions[subtypes.SubtypeFromId(domain, mg.GetPublicId())]).Strings()))
	}
	if outputFields.Has(globals.MemberIdsField) {
		outputOpts = append(outputOpts, handlers.WithMemberIds(memberIds))
	}

	item, err := toProto(ctx, mg, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetManagedGroupResponse{Item: item}, nil
}

// CreateManagedGroup implements the interface pbs.ManagedGroupServiceServer.
func (s Service) CreateManagedGroup(ctx context.Context, req *pbs.CreateManagedGroupRequest) (*pbs.CreateManagedGroupResponse, error) {
	const op = "managed_groups.(Service).CreateManagedGroup"

	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}

	authMeth, authResults := s.parentAndAuthResult(ctx, req.GetItem().GetAuthMethodId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	mg, err := s.createInRepo(ctx, authMeth, req.GetItem())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, mg.GetPublicId(), IdActions[subtypes.SubtypeFromId(domain, mg.GetPublicId())]).Strings()))
	}

	item, err := toProto(ctx, mg, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateManagedGroupResponse{Item: item, Uri: fmt.Sprintf("managed-groups/%s", item.GetId())}, nil
}

// UpdateManagedGroup implements the interface pbs.ManagedGroupServiceServer.
func (s Service) UpdateManagedGroup(ctx context.Context, req *pbs.UpdateManagedGroupRequest) (*pbs.UpdateManagedGroupResponse, error) {
	const op = "managed_groups.(Service).UpdateManagedGroup"

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}

	authMeth, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	mg, err := s.updateInRepo(ctx, authResults.Scope.GetId(), authMeth.GetPublicId(), req)
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, mg.GetPublicId(), IdActions[subtypes.SubtypeFromId(domain, mg.GetPublicId())]).Strings()))
	}

	item, err := toProto(ctx, mg, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateManagedGroupResponse{Item: item}, nil
}

// DeleteManagedGroup implements the interface pbs.ManagedGroupServiceServer.
func (s Service) DeleteManagedGroup(ctx context.Context, req *pbs.DeleteManagedGroupRequest) (*pbs.DeleteManagedGroupResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Delete)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	_, err := s.deleteFromRepo(ctx, authResults.Scope.GetId(), req.GetId())
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (auth.ManagedGroup, []string, error) {
	var out auth.ManagedGroup
	var memberIds []string
	switch subtypes.SubtypeFromId(domain, id) {
	case oidc.Subtype:
		repo, err := s.oidcRepoFn()
		if err != nil {
			return nil, nil, err
		}
		mg, err := repo.LookupManagedGroup(ctx, id)
		if err != nil {
			if errors.IsNotFoundError(err) {
				return nil, nil, handlers.NotFoundErrorf("ManagedGroup %q doesn't exist.", id)
			}
			return nil, nil, err
		}
		ids, err := repo.ListManagedGroupMembershipsByGroup(ctx, mg.GetPublicId())
		if err != nil {
			return nil, nil, err
		}
		if len(ids) > 0 {
			memberIds = make([]string, len(ids))
			for i, v := range ids {
				memberIds[i] = v.MemberId
			}
		}
		out = mg
	default:
		return nil, nil, handlers.NotFoundErrorf("Unrecognized id.")
	}
	return out, memberIds, nil
}

func (s Service) createOidcInRepo(ctx context.Context, am auth.AuthMethod, item *pb.ManagedGroup) (*oidc.ManagedGroup, error) {
	const op = "managed_groups.(Service).createOidcInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing item")
	}
	var opts []oidc.Option
	if item.GetName() != nil {
		opts = append(opts, oidc.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, oidc.WithDescription(item.GetDescription().GetValue()))
	}
	attrs := item.GetOidcManagedGroupAttributes()
	mg, err := oidc.NewManagedGroup(ctx, am.GetPublicId(), attrs.GetFilter(), opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build user for creation: %v.", err)
	}
	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, err
	}

	out, err := repo.CreateManagedGroup(ctx, am.GetScopeId(), mg)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create managed group"))
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create managed group but no error returned from repository.")
	}
	return out, nil
}

func (s Service) createInRepo(ctx context.Context, am auth.AuthMethod, item *pb.ManagedGroup) (auth.ManagedGroup, error) {
	const op = "managed_groups.(Service).createInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing item")
	}
	var out auth.ManagedGroup
	switch subtypes.SubtypeFromId(domain, am.GetPublicId()) {
	case oidc.Subtype:
		am, err := s.createOidcInRepo(ctx, am, item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if am == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create managed group but no error returned from repository.")
		}
		out = am
	}
	return out, nil
}

func (s Service) updateOidcInRepo(ctx context.Context, scopeId, amId, id string, mask []string, item *pb.ManagedGroup) (*oidc.ManagedGroup, error) {
	const op = "managed_groups.(Service).updateOidcInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil managed group.")
	}
	mg := oidc.AllocManagedGroup()
	mg.PublicId = id
	if item.GetName() != nil {
		mg.Name = item.GetName().GetValue()
	}
	if item.GetDescription() != nil {
		mg.Description = item.GetDescription().GetValue()
	}
	// Set this regardless; it'll only take effect if the masks contain the value
	mg.Filter = item.GetOidcManagedGroupAttributes().GetFilter()

	version := item.GetVersion()

	dbMask := oidcMaskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, rowsUpdated, err := repo.UpdateManagedGroup(ctx, scopeId, mg, version, dbMask)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update managed group"))
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Managed Group %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, authMethodId string, req *pbs.UpdateManagedGroupRequest) (auth.ManagedGroup, error) {
	const op = "managed_groups.(Service).updateInRepo"
	var out auth.ManagedGroup
	switch subtypes.SubtypeFromId(domain, req.GetId()) {
	case oidc.Subtype:
		mg, err := s.updateOidcInRepo(ctx, scopeId, authMethodId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if mg == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to update managed group but no error returned from repository.")
		}
		out = mg
	}
	return out, nil
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	const op = "managed_groups.(Service).deleteFromRepo"
	var rows int
	var err error
	switch subtypes.SubtypeFromId(domain, id) {
	case oidc.Subtype:
		repo, iErr := s.oidcRepoFn()
		if iErr != nil {
			return false, iErr
		}
		rows, err = repo.DeleteManagedGroup(ctx, scopeId, id)
	}
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(ctx, err, op)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, authMethodId string) ([]auth.ManagedGroup, error) {
	const op = "managed_groups.(Service).listFromRepo"

	var outUl []auth.ManagedGroup
	switch subtypes.SubtypeFromId(domain, authMethodId) {
	case oidc.Subtype:
		oidcRepo, err := s.oidcRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		oidcl, err := oidcRepo.ListManagedGroups(ctx, authMethodId)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		for _, a := range oidcl {
			outUl = append(outUl, a)
		}
	}
	return outUl, nil
}

func (s Service) parentAndAuthResult(ctx context.Context, id string, a action.Type) (auth.AuthMethod, requestauth.VerifyResults) {
	const op = "managed_groups.(Service)."
	res := requestauth.VerifyResults{}
	oidcRepo, err := s.oidcRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}

	var parentId string
	opts := []requestauth.Option{requestauth.WithType(resource.ManagedGroup), requestauth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
	default:
		switch subtypes.SubtypeFromId(domain, id) {
		case oidc.Subtype:
			acct, err := oidcRepo.LookupManagedGroup(ctx, id)
			if err != nil {
				res.Error = err
				return nil, res
			}
			if acct == nil {
				res.Error = handlers.NotFoundError()
				return nil, res
			}
			parentId = acct.GetAuthMethodId()
		default:
			res.Error = errors.New(ctx, errors.InvalidPublicId, op, "unrecognized managed group subtype")
			return nil, res
		}
		opts = append(opts, requestauth.WithId(id))
	}

	var authMeth auth.AuthMethod
	switch subtypes.SubtypeFromId(domain, parentId) {
	case oidc.Subtype:
		am, err := oidcRepo.LookupAuthMethod(ctx, parentId)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if am == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		authMeth = am
		opts = append(opts, requestauth.WithScopeId(am.GetScopeId()))
	default:
		res.Error = errors.New(ctx, errors.InvalidPublicId, op, "unrecognized auth method subtype")
		return nil, res
	}
	opts = append(opts, requestauth.WithPin(parentId))
	return authMeth, requestauth.Verify(ctx, opts...)
}

func toProto(ctx context.Context, in auth.ManagedGroup, opt ...handlers.Option) (*pb.ManagedGroup, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building managed group proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.ManagedGroup{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.AuthMethodIdField) {
		out.AuthMethodId = in.GetAuthMethodId()
	}
	if outputFields.Has(globals.DescriptionField) && in.GetDescription() != "" {
		out.Description = &wrapperspb.StringValue{Value: in.GetDescription()}
	}
	if outputFields.Has(globals.NameField) && in.GetName() != "" {
		out.Name = &wrapperspb.StringValue{Value: in.GetName()}
	}
	if outputFields.Has(globals.CreatedTimeField) {
		out.CreatedTime = in.GetCreateTime().GetTimestamp()
	}
	if outputFields.Has(globals.UpdatedTimeField) {
		out.UpdatedTime = in.GetUpdateTime().GetTimestamp()
	}
	if outputFields.Has(globals.VersionField) {
		out.Version = in.GetVersion()
	}
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
	}
	if outputFields.Has(globals.MemberIdsField) {
		out.MemberIds = opts.WithMemberIds
	}
	switch i := in.(type) {
	case *oidc.ManagedGroup:
		if outputFields.Has(globals.TypeField) {
			out.Type = oidc.Subtype.String()
		}
		if !outputFields.Has(globals.AttributesField) {
			break
		}
		attrs := &pb.OidcManagedGroupAttributes{
			Filter: i.GetFilter(),
		}
		out.Attrs = &pb.ManagedGroup_OidcManagedGroupAttributes{
			OidcManagedGroupAttributes: attrs,
		}
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetManagedGroupRequest) error {
	const op = "managed_groups.validateGetRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, intglobals.OidcManagedGroupPrefix)
}

func validateCreateRequest(req *pbs.CreateManagedGroupRequest) error {
	const op = "managed_groups.validateCreateRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetAuthMethodId() == "" {
			badFields[globals.AuthMethodIdField] = "This field is required."
		}
		switch subtypes.SubtypeFromId(domain, req.GetItem().GetAuthMethodId()) {
		case oidc.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != oidc.Subtype.String() {
				badFields[globals.TypeField] = "Doesn't match the parent resource's type."
			}
			attrs := req.GetItem().GetOidcManagedGroupAttributes()
			if attrs == nil {
				badFields[globals.AttributesField] = "Attribute fields is required."
			} else {
				if attrs.Filter == "" {
					badFields[attrFilterField] = "This field is required."
				} else {
					if _, err := bexpr.CreateEvaluator(attrs.Filter); err != nil {
						badFields[attrFilterField] = fmt.Sprintf("Error evaluating submitted filter expression: %v.", err)
					}
				}
			}
		default:
			badFields[globals.AuthMethodIdField] = "Unknown auth method type from ID."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateManagedGroupRequest) error {
	const op = "managed_groups.validateUpdateRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch subtypes.SubtypeFromId(domain, req.GetId()) {
		case oidc.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != oidc.Subtype.String() {
				badFields[globals.TypeField] = "Cannot modify the resource type."
			}
			attrs := req.GetItem().GetOidcManagedGroupAttributes()
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), attrFilterField) {
				switch {
				case attrs == nil:
					badFields["attributes"] = "Attributes field not supplied request"
				default:
					if attrs.Filter == "" {
						badFields[attrFilterField] = "Field cannot be empty."
					} else {
						if _, err := bexpr.CreateEvaluator(attrs.Filter); err != nil {
							badFields[attrFilterField] = fmt.Sprintf("Error evaluating submitted filter expression: %v.", err)
						}
					}
				}
			}
		default:
			badFields[globals.IdField] = "Unrecognized resource type."
		}
		return badFields
	}, intglobals.OidcManagedGroupPrefix)
}

func validateDeleteRequest(req *pbs.DeleteManagedGroupRequest) error {
	const op = "managed_groups.validateDeleteRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, intglobals.OidcManagedGroupPrefix)
}

func validateListRequest(req *pbs.ListManagedGroupsRequest) error {
	const op = "managed_groups.validateListRequest"
	if req == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil request")
	}
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetAuthMethodId()), oidc.AuthMethodPrefix) {
		badFields[globals.AuthMethodIdField] = "Invalid formatted identifier."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields[globals.FilterField] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}
