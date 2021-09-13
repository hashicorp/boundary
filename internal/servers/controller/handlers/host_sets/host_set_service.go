package host_sets

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
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
	pluginRepoFn common.PluginHostRepoFactory
}

var _ pbs.HostSetServiceServer = Service{}

// NewService returns a host set Service which handles host set related requests to boundary and uses the provided
// repositories for storage and retrieval.
func NewService(staticRepoFn common.StaticRepoFactory, pluginRepoFn common.PluginHostRepoFactory) (Service, error) {
	const op = "host_sets.NewService"
	if staticRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing static repository")
	}
	if pluginRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing plugin repository")
	}
	return Service{staticRepoFn: staticRepoFn, pluginRepoFn: pluginRepoFn}, nil
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
	hs, hosts, err := s.updateInRepo(ctx, authResults.Scope.GetId(), cat.GetPublicId(), req)
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

func (s Service) getFromRepo(ctx context.Context, id string) (host.Set, []host.Host, error) {
	var hs host.Set
	var hl []host.Host
	switch host.SubtypeFromId(id) {
	case static.Subtype:
		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, nil, err
		}
		hset, hosts, err := repo.LookupSet(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if hset == nil {
			return nil, nil, handlers.NotFoundErrorf("Host Set %q doesn't exist.", id)
		}
		for _, h := range hosts {
			hl = append(hl, h)
		}
		hs = hset
	case plugin.Subtype:
		repo, err := s.pluginRepoFn()
		if err != nil {
			return nil, nil, err
		}
		hset, err := repo.LookupSet(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if hset == nil {
			return nil, nil, handlers.NotFoundErrorf("Host Set %q doesn't exist.", id)
		}
		hs = hset
	}
	return hs, hl, nil
}

func (s Service) createInRepo(ctx context.Context, scopeId, catalogId string, item *pb.HostSet) (host.Set, error) {
	const op = "host_sets.(Service).createInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing item")
	}
	var hSet host.Set
	switch host.SubtypeFromId(catalogId) {
	case static.Subtype:
		h, err := toStorageStaticSet(ctx, catalogId, item)
		if err != nil {
			return nil, err
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
		hSet = out
	case plugin.Subtype:
		h, err := toStoragePluginSet(ctx, catalogId, item)
		repo, err := s.pluginRepoFn()
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
		hSet = out
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unrecognized catalog type")
	}
	return hSet, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, catalogId string, req *pbs.UpdateHostSetRequest) (host.Set, []host.Host, error) {
	const op = "host_sets.(Service).updateInRepo"
	item := req.GetItem()
	h, err := toStorageStaticSet(ctx, catalogId, item)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to build host set for update"))
	}
	h.PublicId = req.GetId()
	dbMask := maskManager.Translate(req.GetUpdateMask().GetPaths())
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
		return nil, nil, handlers.NotFoundErrorf("Host Set %q doesn't exist or incorrect version provided.", req.GetId())
	}
	var hl []host.Host
	for _, h := range m {
		hl = append(hl, h)
	}
	return out, hl, nil
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

func (s Service) listFromRepo(ctx context.Context, catalogId string) ([]host.Set, error) {
	const op = "host_sets.(Service).listFromRepo"
	var sets []host.Set
	switch host.SubtypeFromId(catalogId) {
	case static.Subtype:
		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, err
		}
		sl, err := repo.ListSets(ctx, catalogId)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		for _, a := range sl {
			sets = append(sets, a)
		}
	case plugin.Subtype:
		repo, err := s.pluginRepoFn()
		if err != nil {
			return nil, err
		}
		sl, err := repo.ListSets(ctx, catalogId)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		for _, a := range sl {
			sets = append(sets, a)
		}
	}
	return sets, nil
}

func (s Service) addInRepo(ctx context.Context, scopeId, setId string, hostIds []string, version uint32) (*static.HostSet, []host.Host, error) {
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
	var hl []host.Host
	for _, h := range m {
		hl = append(hl, h)
	}
	return out, hl, nil
}

func (s Service) setInRepo(ctx context.Context, scopeId, setId string, hostIds []string, version uint32) (*static.HostSet, []host.Host, error) {
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
	var hl []host.Host
	for _, h := range m {
		hl = append(hl, h)
	}
	return out, hl, nil
}

func (s Service) removeInRepo(ctx context.Context, scopeId, setId string, hostIds []string, version uint32) (*static.HostSet, []host.Host, error) {
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
	var hl []host.Host
	for _, h := range m {
		hl = append(hl, h)
	}
	return out, hl, nil
}

func (s Service) parentAndAuthResult(ctx context.Context, id string, a action.Type) (host.Catalog, auth.VerifyResults) {
	res := auth.VerifyResults{}

	staticRepo, err := s.staticRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}
	pluginRepo, err := s.pluginRepoFn()
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
		var set host.Set
		switch host.SubtypeFromId(id) {
		case static.Subtype:
			ss, _, err := staticRepo.LookupSet(ctx, id)
			if err != nil {
				res.Error = err
				return nil, res
			}
			if ss == nil {
				res.Error = handlers.NotFoundError()
				return nil, res
			}
			set = ss
		case plugin.Subtype:
			ps, err := pluginRepo.LookupSet(ctx, id)
			if err != nil {
				res.Error = err
				return nil, res
			}
			if ps == nil {
				res.Error = handlers.NotFoundError()
				return nil, res
			}
			set = ps
		}
		parentId = set.GetCatalogId()
		opts = append(opts, auth.WithId(id))
	}

	var cat host.Catalog
	switch host.SubtypeFromId(id) {
	case static.Subtype:
		cs, err := staticRepo.LookupCatalog(ctx, parentId)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if cs == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		cat = cs
	case plugin.Subtype:
		pc, err := pluginRepo.LookupCatalog(ctx, parentId)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if pc == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		cat = pc
	}
	opts = append(opts, auth.WithScopeId(cat.GetScopeId()), auth.WithPin(parentId))
	return cat, auth.Verify(ctx, opts...)
}

func toProto(ctx context.Context, in host.Set, hosts []host.Host, opt ...handlers.Option) (*pb.HostSet, error) {
	const op = "host_set_service.toProto"
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
		switch host.SubtypeFromId(in.GetPublicId()) {
		case static.Subtype:
			out.Type = static.Subtype.String()
		case plugin.Subtype:
			out.Type = "plugin"
			idParts := strings.Split(in.GetPublicId(), "_")
			if len(idParts) > 2 {
				out.Type = idParts[1]
			}
		}
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

	if outputFields.Has(globals.AttributesField) {
		switch h := in.(type) {
		case *plugin.HostSet:
			attrs := map[string]interface{}{}
			err := json.Unmarshal(h.Attributes, &attrs)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			if len(attrs) > 0 {
				out.Attributes, err = structpb.NewStruct(attrs)
				if err != nil {
					return nil, errors.Wrap(ctx, err, op)
				}
			}
		}
	}

	return &out, nil
}

func toStorageStaticSet(ctx context.Context, catalogId string, item *pb.HostSet) (*static.HostSet, error) {
	const op = "host_set_service.toStorageStaticSet"
	var opts []static.Option
	if item.GetName() != nil {
		opts = append(opts, static.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, static.WithDescription(item.GetDescription().GetValue()))
	}
	hs, err := static.NewHostSet(catalogId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to build host set for creation"))
	}
	return hs, nil
}

func toStoragePluginSet(ctx context.Context, catalogId string, item *pb.HostSet) (*plugin.HostSet, error) {
	const op = "host_set_service.toStoragePluginSet"
	var opts []plugin.Option
	if item.GetName() != nil {
		opts = append(opts, plugin.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, plugin.WithDescription(item.GetDescription().GetValue()))
	}
	if item.GetAttributes() != nil {
		opts = append(opts, plugin.WithAttributes(item.GetAttributes().AsMap()))
	}
	hs, err := plugin.NewHostSet(ctx, catalogId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to build host set for creation"))
	}
	return hs, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
//  * The type asserted by the ID and/or field is known
//  * If relevant, the type derived from the id prefix matches what is claimed by the type field
func validateGetRequest(req *pbs.GetHostSetRequest) error {
	pluginPrefix := plugin.HostSetPrefix
	idParts := strings.Split(req.GetId(), "_")
	if len(idParts) > 2 && idParts[0] == plugin.HostSetPrefix {
		pluginPrefix = strings.Join(idParts[:2], "_")
	}

	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, static.HostSetPrefix, pluginPrefix)
}

func validateCreateRequest(req *pbs.CreateHostSetRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		pluginPrefix := plugin.HostCatalogPrefix
		idParts := strings.Split(req.GetItem().GetHostCatalogId(), "_")
		if len(idParts) > 2 && idParts[0] == plugin.HostCatalogPrefix {
			pluginPrefix = strings.Join(idParts[:2], "_")
		}

		if !handlers.ValidId(handlers.Id(req.GetItem().GetHostCatalogId()), static.HostCatalogPrefix, pluginPrefix) {
			badFields["host_catalog_id"] = "The field is incorrectly formatted."
		}
		switch host.SubtypeFromId(req.GetItem().GetHostCatalogId()) {
		case static.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != static.Subtype.String() {
				badFields["type"] = "Doesn't match the parent resource's type."
			}
		case plugin.Subtype:
			// TODO: Remove this check when plugin id prefixes can differ from plugin name
			if req.GetItem().GetType() == "" {
				break
			}
			idParts := strings.Split(req.GetItem().GetHostCatalogId(), "_")
			if len(idParts) < 2 {
				badFields["host_catalog_id"] = "The field is incorrectly formatted for a plugin id."
				break
			}
			plgType := idParts[1]
			if plgType != req.GetItem().GetType() {
				badFields["type"] = "This type must match the type of the host catalog."
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
	pluginPrefix := plugin.HostCatalogPrefix
	idParts := strings.Split(req.GetHostCatalogId(), "_")
	if len(idParts) > 2 && idParts[0] == plugin.HostCatalogPrefix {
		pluginPrefix = strings.Join(idParts[:2], "_")
	}

	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetHostCatalogId()), static.HostCatalogPrefix, pluginPrefix) {
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
