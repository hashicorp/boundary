package host_sets

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/hostsets"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.ActionSet{
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
		action.AddHosts,
		action.SetHosts,
		action.RemoveHosts,
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
	if maskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.HostSet{}}, handlers.MaskSource{&pb.HostSet{}}); err != nil {
		panic(err)
	}
}

type Service struct {
	pbs.UnimplementedHostSetServiceServer

	staticRepoFn common.StaticRepoFactory
}

var _ pbs.HostSetServiceServer = Service{}

// NewService returns a host set Service which handles host set related requests to boundary and uses the provided
// repositories for storage and retrieval.
func NewService(repoFn common.StaticRepoFactory) (Service, error) {
	const op = "host_sets.NewService"
	if repoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing static repository")
	}
	return Service{staticRepoFn: repoFn}, nil
}

func (s Service) ListHostSets(ctx context.Context, req *pbs.ListHostSetsRequest) (*pbs.ListHostSetsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetHostCatalogId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hl, err := s.listFromRepo(ctx, req.GetHostCatalogId())
	if err != nil {
		return nil, err
	}
	if len(hl) == 0 {
		return &pbs.ListHostSetsResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.HostSet, 0, len(hl))

	res := perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.HostSet,
		Pin:     req.GetHostCatalogId(),
	}
	for _, item := range hl {
		res.Id = item.GetPublicId()
		authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res)).Strings()
		if len(authorizedActions) == 0 {
			continue
		}

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
		}

		item, err := toProto(ctx, item, nil, outputOpts...)
		if err != nil {
			return nil, err
		}

		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListHostSetsResponse{Items: finalItems}, nil
}

// GetHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) GetHostSet(ctx context.Context, req *pbs.GetHostSetRequest) (*pbs.GetHostSetResponse, error) {
	const op = "host_sets.(Service).GetHostSet"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hs, hosts, err := s.getFromRepo(ctx, req.GetId())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hs.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, hs, hosts, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetHostSetResponse{Item: item}, nil
}

// CreateHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) CreateHostSet(ctx context.Context, req *pbs.CreateHostSetRequest) (*pbs.CreateHostSetResponse, error) {
	const op = "host_sets.(Service).CreateHostSet"

	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetItem().GetHostCatalogId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hs, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem().GetHostCatalogId(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hs.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, hs, nil, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateHostSetResponse{
		Item: item,
		Uri:  fmt.Sprintf("host-sets/%s", item.GetId()),
	}, nil
}

// UpdateHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) UpdateHostSet(ctx context.Context, req *pbs.UpdateHostSetRequest) (*pbs.UpdateHostSetResponse, error) {
	const op = "host_sets.(Service).UpdateHostSet"

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	cat, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hs, hosts, err := s.updateInRepo(ctx, authResults.Scope.GetId(), cat.GetPublicId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hs.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, hs, hosts, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateHostSetResponse{Item: item}, nil
}

// DeleteHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) DeleteHostSet(ctx context.Context, req *pbs.DeleteHostSetRequest) (*pbs.DeleteHostSetResponse, error) {
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

// AddHostSetHosts implements the interface pbs.HostSetServiceServer.
func (s Service) AddHostSetHosts(ctx context.Context, req *pbs.AddHostSetHostsRequest) (*pbs.AddHostSetHostsResponse, error) {
	const op = "host_sets.(Service).AddHostSetHosts"

	if err := validateAddRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.AddHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hs, hosts, err := s.addInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetHostIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hs.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, hs, hosts, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.AddHostSetHostsResponse{Item: item}, nil
}

// SetHostSetHosts implements the interface pbs.HostSetServiceServer.
func (s Service) SetHostSetHosts(ctx context.Context, req *pbs.SetHostSetHostsRequest) (*pbs.SetHostSetHostsResponse, error) {
	const op = "host_sets.(Service).SetHostSetHosts"

	if err := validateSetRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.SetHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hs, hosts, err := s.setInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetHostIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hs.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, hs, hosts, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetHostSetHostsResponse{Item: item}, nil
}

// RemoveHostSetHosts implements the interface pbs.HostSetServiceServer.
func (s Service) RemoveHostSetHosts(ctx context.Context, req *pbs.RemoveHostSetHostsRequest) (*pbs.RemoveHostSetHostsResponse, error) {
	const op = "host_sets.(Service).RemoveHostSetHosts"

	if err := validateRemoveRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.RemoveHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hs, hosts, err := s.removeInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetHostIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hs.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, hs, hosts, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveHostSetHostsResponse{Item: item}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*static.HostSet, []*static.Host, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, nil, err
	}
	h, m, err := repo.LookupSet(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if h == nil {
		return nil, nil, handlers.NotFoundErrorf("Host Set %q doesn't exist.", id)
	}
	return h, m, nil
}

func (s Service) createInRepo(ctx context.Context, scopeId, catalogId string, item *pb.HostSet) (*static.HostSet, error) {
	const op = "host_sets.(Service).createInRepo"
	var opts []static.Option
	if item.GetName() != nil {
		opts = append(opts, static.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, static.WithDescription(item.GetDescription().GetValue()))
	}
	h, err := static.NewHostSet(catalogId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to build host set for creation"))
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateSet(ctx, scopeId, h)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create host set"))
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create host set but no error returned from repository.")
	}
	return out, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, catalogId, id string, mask []string, item *pb.HostSet) (*static.HostSet, []*static.Host, error) {
	const op = "host_sets.(Service).updateInRepo"
	var opts []static.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, static.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, static.WithName(name.GetValue()))
	}
	h, err := static.NewHostSet(catalogId, opts...)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to build host set for update"))
	}
	h.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, nil, err
	}
	out, m, rowsUpdated, err := repo.UpdateSet(ctx, scopeId, h, item.GetVersion(), dbMask)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update host set"))
	}
	if rowsUpdated == 0 {
		return nil, nil, handlers.NotFoundErrorf("Host Set %q doesn't exist or incorrect version provided.", id)
	}
	return out, m, nil
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	const op = "host_sets.(Service).deleteFromRepo"
	repo, err := s.staticRepoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteSet(ctx, scopeId, id)
	if err != nil {
		return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete host"))
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, catalogId string) ([]*static.HostSet, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	hl, err := repo.ListSets(ctx, catalogId)
	if err != nil {
		return nil, err
	}
	return hl, nil
}

func (s Service) addInRepo(ctx context.Context, scopeId, setId string, hostIds []string, version uint32) (*static.HostSet, []*static.Host, error) {
	const op = "host_sets.(Service).addInRepo"
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, nil, err
	}
	_, err = repo.AddSetMembers(ctx, scopeId, setId, version, strutil.RemoveDuplicates(hostIds, false))
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to add hosts to host set"))
	}
	out, m, err := repo.LookupSet(ctx, setId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up host set after adding hosts"))
	}
	if out == nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup host set after adding hosts to it.")
	}
	return out, m, nil
}

func (s Service) setInRepo(ctx context.Context, scopeId, setId string, hostIds []string, version uint32) (*static.HostSet, []*static.Host, error) {
	const op = "host_sets.(Service).setInRepo"
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	_, _, err = repo.SetSetMembers(ctx, scopeId, setId, version, strutil.RemoveDuplicates(hostIds, false))
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to set hosts in host set"))
	}

	out, m, err := repo.LookupSet(ctx, setId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up host set after setting hosts"))
	}
	if out == nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup host set after setting hosts for it.")
	}
	return out, m, nil
}

func (s Service) removeInRepo(ctx context.Context, scopeId, setId string, hostIds []string, version uint32) (*static.HostSet, []*static.Host, error) {
	const op = "host_sets.(Service).removeInRepo"
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	_, err = repo.DeleteSetMembers(ctx, scopeId, setId, version, strutil.RemoveDuplicates(hostIds, false))
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to remove hosts from host set"))
	}
	out, m, err := repo.LookupSet(ctx, setId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up host set"))
	}
	if out == nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup host set after removing hosts from it.")
	}
	return out, m, nil
}

func (s Service) parentAndAuthResult(ctx context.Context, id string, a action.Type) (*static.HostCatalog, auth.VerifyResults) {
	res := auth.VerifyResults{}
	repo, err := s.staticRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.HostSet), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
	default:
		set, _, err := repo.LookupSet(ctx, id)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if set == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		parentId = set.GetCatalogId()
		opts = append(opts, auth.WithId(id))
	}

	cat, err := repo.LookupCatalog(ctx, parentId)
	if err != nil {
		res.Error = err
		return nil, res
	}
	if cat == nil {
		res.Error = handlers.NotFoundError()
		return nil, res
	}
	opts = append(opts, auth.WithScopeId(cat.GetScopeId()), auth.WithPin(parentId))
	return cat, auth.Verify(ctx, opts...)
}

func toProto(ctx context.Context, in *static.HostSet, hosts []*static.Host, opt ...handlers.Option) (*pb.HostSet, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building hostset proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.HostSet{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.HostCatalogIdField) {
		out.HostCatalogId = in.GetCatalogId()
	}
	if outputFields.Has(globals.TypeField) {
		out.Type = static.Subtype.String()
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
	if outputFields.Has(globals.HostIdsField) {
		for _, h := range hosts {
			out.HostIds = append(out.HostIds, h.GetPublicId())
		}
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
//  * The type asserted by the ID and/or field is known
//  * If relevant, the type derived from the id prefix matches what is claimed by the type field
func validateGetRequest(req *pbs.GetHostSetRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, static.HostSetPrefix)
}

func validateCreateRequest(req *pbs.CreateHostSetRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetHostCatalogId()), static.HostCatalogPrefix) {
			badFields["host_catalog_id"] = "The field is incorrectly formatted."
		}
		switch host.SubtypeFromId(req.GetItem().GetHostCatalogId()) {
		case static.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != static.Subtype.String() {
				badFields["type"] = "Doesn't match the parent resource's type."
			}
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateHostSetRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch host.SubtypeFromId(req.GetId()) {
		case static.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != static.Subtype.String() {
				badFields["type"] = "Cannot modify the resource type."
			}
		}
		return badFields
	}, static.HostSetPrefix)
}

func validateDeleteRequest(req *pbs.DeleteHostSetRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, static.HostSetPrefix)
}

func validateListRequest(req *pbs.ListHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetHostCatalogId()), static.HostCatalogPrefix) {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddRequest(req *pbs.AddHostSetHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), static.HostSetPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetHostIds()) == 0 {
		badFields["host_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetHostIds() {
		if !handlers.ValidId(handlers.Id(id), static.HostPrefix) {
			badFields["host_ids"] = "Incorrectly formatted host identifier."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetRequest(req *pbs.SetHostSetHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), static.HostSetPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	for _, id := range req.GetHostIds() {
		if !handlers.ValidId(handlers.Id(id), static.HostPrefix) {
			badFields["host_ids"] = "Incorrectly formatted host identifier."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveRequest(req *pbs.RemoveHostSetHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), static.HostSetPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetHostIds()) == 0 {
		badFields["host_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetHostIds() {
		if !handlers.ValidId(handlers.Id(id), static.HostPrefix) {
			badFields["host_ids"] = "Incorrectly formatted host identifier."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
