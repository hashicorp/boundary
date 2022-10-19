package host_catalogs

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/host_sets"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/hosts"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/plugin"
	pluginstore "github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/perms"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	"github.com/mr-tron/base58"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	staticMaskManager handlers.MaskManager
	pluginMaskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.ActionSet{
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.ActionSet{
		action.Create,
		action.List,
	}

	collectionTypeMap = map[subtypes.Subtype]map[resource.Type]action.ActionSet{
		static.Subtype: {
			resource.HostSet: host_sets.CollectionActions,
			resource.Host:    hosts.CollectionActions,
		},
		plugin.Subtype: {
			resource.HostSet: host_sets.CollectionActions,
			resource.Host: action.ActionSet{
				action.List,
			},
		},
	}
)

const domain = "host"

func init() {
	var err error
	if staticMaskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.HostCatalog{}}, handlers.MaskSource{&pb.HostCatalog{}}); err != nil {
		panic(err)
	}
	if pluginMaskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&pluginstore.HostCatalog{}}, handlers.MaskSource{&pb.HostCatalog{}}); err != nil {
		panic(err)
	}
}

type Service struct {
	pbs.UnsafeHostCatalogServiceServer

	staticRepoFn     common.StaticRepoFactory
	pluginHostRepoFn common.PluginHostRepoFactory
	pluginRepoFn     common.HostPluginRepoFactory
	iamRepoFn        common.IamRepoFactory
}

var _ pbs.HostCatalogServiceServer = (*Service)(nil)

// NewService returns a host catalog Service which handles host catalog related requests to boundary and uses the provided
// repositories for storage and retrieval.
func NewService(repoFn common.StaticRepoFactory, pluginHostRepoFn common.PluginHostRepoFactory, hostPluginRepoFn common.HostPluginRepoFactory, iamRepoFn common.IamRepoFactory) (Service, error) {
	const op = "host_catalogs.NewService"
	if repoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing static repository")
	}
	if pluginHostRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing plugin host repository")
	}
	if hostPluginRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing host plugin repository")
	}
	if iamRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing iam repository")
	}
	return Service{staticRepoFn: repoFn, pluginHostRepoFn: pluginHostRepoFn, pluginRepoFn: hostPluginRepoFn, iamRepoFn: iamRepoFn}, nil
}

func (s Service) ListHostCatalogs(ctx context.Context, req *pbs.ListHostCatalogsRequest) (*pbs.ListHostCatalogsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		// If it's forbidden, and it's a recursive request, and they're
		// successfully authenticated but just not authorized, keep going as we
		// may have authorization on downstream projects. Or, if they've not
		// authenticated, still process in case u_anon has permissions.
		if (authResults.Error == handlers.ForbiddenError() || authResults.Error == handlers.UnauthenticatedError()) &&
			req.GetRecursive() &&
			authResults.AuthenticationFinished {
		} else {
			return nil, authResults.Error
		}
	}

	scopeIds, scopeInfoMap, err := scopeids.GetListingScopeIds(
		ctx, s.iamRepoFn, authResults, req.GetScopeId(), resource.HostCatalog, req.GetRecursive())
	if err != nil {
		return nil, err
	}
	// If no scopes match, return an empty response
	if len(scopeIds) == 0 {
		return &pbs.ListHostCatalogsResponse{}, nil
	}

	items, pluginInfoMap, err := s.listFromRepo(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return &pbs.ListHostCatalogsResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.HostCatalog, 0, len(items))
	res := perms.Resource{
		Type: resource.HostCatalog,
	}
	for _, item := range items {
		res.Id = item.GetPublicId()
		res.ScopeId = item.GetProjectId()
		authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res)).Strings()
		if len(authorizedActions) == 0 {
			continue
		}

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserData.User.Id)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(scopeInfoMap[item.GetProjectId()]))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
		}
		if outputFields.Has(globals.AuthorizedCollectionActionsField) {
			var subtype subtypes.Subtype
			switch item.(type) {
			case *static.HostCatalog:
				subtype = static.Subtype
			case *plugin.HostCatalog:
				subtype = plugin.Subtype
			}
			if subtype != "" {
				collectionActions, err := auth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap[subtype], authResults.Scope.Id, item.GetPublicId())
				if err != nil {
					return nil, err
				}
				outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
			}
		}
		switch hc := item.(type) {
		case *plugin.HostCatalog:
			if plgInfo, ok := pluginInfoMap[hc.GetPluginId()]; ok {
				outputOpts = append(outputOpts, handlers.WithPlugin(plgInfo))
			}
		}

		item, err := toProto(ctx, item, outputOpts...)
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
	return &pbs.ListHostCatalogsResponse{Items: finalItems}, nil
}

// GetHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) GetHostCatalog(ctx context.Context, req *pbs.GetHostCatalogRequest) (*pbs.GetHostCatalogResponse, error) {
	const op = "host_catalogs.(Service).GetostCatalog"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hc, plg, err := s.getFromRepo(ctx, req.GetId())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hc.GetPublicId(), IdActions).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		var subtype subtypes.Subtype
		switch hc.(type) {
		case *static.HostCatalog:
			subtype = static.Subtype
		case *plugin.HostCatalog:
			subtype = plugin.Subtype
		}
		if subtype != "" {
			collectionActions, err := auth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap[subtype], authResults.Scope.Id, hc.GetPublicId())
			if err != nil {
				return nil, err
			}
			outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
		}
	}
	if plg != nil {
		outputOpts = append(outputOpts, handlers.WithPlugin(plg))
	}

	item, err := toProto(ctx, hc, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetHostCatalogResponse{Item: item}, nil
}

// CreateHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) CreateHostCatalog(ctx context.Context, req *pbs.CreateHostCatalogRequest) (*pbs.CreateHostCatalogResponse, error) {
	const op = "host_catalogs.(Service).CreateHostCatalog"

	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hc, plg, err := s.createInRepo(ctx, authResults.Scope.GetId(), req)
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 4)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hc.GetPublicId(), IdActions).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		var subtype subtypes.Subtype
		switch hc.(type) {
		case *static.HostCatalog:
			subtype = static.Subtype
		case *plugin.HostCatalog:
			subtype = plugin.Subtype
		}
		if subtype != "" {
			collectionActions, err := auth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap[subtype], authResults.Scope.Id, hc.GetPublicId())
			if err != nil {
				return nil, err
			}
			outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
		}
	}
	if plg != nil {
		outputOpts = append(outputOpts, handlers.WithPlugin(plg))
	}

	item, err := toProto(ctx, hc, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateHostCatalogResponse{
		Item: item,
		Uri:  fmt.Sprintf("host-catalogs/%s", item.GetId()),
	}, nil
}

// UpdateHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) UpdateHostCatalog(ctx context.Context, req *pbs.UpdateHostCatalogRequest) (*pbs.UpdateHostCatalogResponse, error) {
	const op = "host_catalogs.(Service).UpdateHostCatalog"

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hc, plg, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req)
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if plg != nil {
		outputOpts = append(outputOpts, handlers.WithPlugin(plg))
	}
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hc.GetPublicId(), IdActions).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		var subtype subtypes.Subtype
		switch hc.(type) {
		case *static.HostCatalog:
			subtype = static.Subtype
		case *plugin.HostCatalog:
			subtype = plugin.Subtype
		}
		if subtype != "" {
			collectionActions, err := auth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap[subtype], authResults.Scope.Id, hc.GetPublicId())
			if err != nil {
				return nil, err
			}
			outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
		}
	}
	item, err := toProto(ctx, hc, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateHostCatalogResponse{Item: item}, nil
}

// DeleteHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) DeleteHostCatalog(ctx context.Context, req *pbs.DeleteHostCatalogRequest) (*pbs.DeleteHostCatalogResponse, error) {
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
	return nil, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (host.Catalog, *plugins.PluginInfo, error) {
	var plg *plugins.PluginInfo
	var cat host.Catalog
	switch subtypes.SubtypeFromId(domain, id) {
	case static.Subtype:
		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, nil, err
		}
		hc, err := repo.LookupCatalog(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if hc == nil {
			return nil, nil, handlers.NotFoundErrorf("Host Catalog %q doesn't exist.", id)
		}
		cat = hc
	case plugin.Subtype:
		repo, err := s.pluginHostRepoFn()
		if err != nil {
			return nil, nil, err
		}
		hc, hcplg, err := repo.LookupCatalog(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if hc == nil {
			return nil, nil, handlers.NotFoundErrorf("Host Catalog %q doesn't exist.", id)
		}
		cat = hc
		plg = toPluginInfo(hcplg)
	}
	return cat, plg, nil
}

func (s Service) listFromRepo(ctx context.Context, projectIds []string) ([]host.Catalog, map[string]*plugins.PluginInfo, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, nil, err
	}
	ul, err := repo.ListCatalogs(ctx, projectIds)
	if err != nil {
		return nil, nil, err
	}
	var res []host.Catalog
	for _, c := range ul {
		res = append(res, c)
	}
	pluginRepo, err := s.pluginHostRepoFn()
	if err != nil {
		return nil, nil, err
	}
	pl, plgs, err := pluginRepo.ListCatalogs(ctx, projectIds)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range pl {
		res = append(res, c)
	}
	pluginsMap := make(map[string]*plugins.PluginInfo, len(plgs))
	for _, plg := range plgs {
		pluginsMap[plg.GetPublicId()] = toPluginInfo(plg)
	}

	return res, pluginsMap, nil
}

func (s Service) createStaticInRepo(ctx context.Context, projId string, item *pb.HostCatalog) (*static.HostCatalog, error) {
	const op = "host_catalogs.(Service).createStaticInRepo"
	h, err := toStorageStaticCatalog(ctx, projId, item)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build catalog for creation"))
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, err := repo.CreateCatalog(ctx, h)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create host catalog"))
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create host catalog but no error returned from repository.")
	}
	return out, nil
}

func (s Service) createPluginInRepo(ctx context.Context, projId string, req *pbs.CreateHostCatalogRequest) (*plugin.HostCatalog, *plugins.PluginInfo, error) {
	const op = "host_catalogs.(Service).createPluginInRepo"
	item := req.GetItem()
	pluginId := item.GetPluginId()
	if pluginId == "" {
		plgRepo, err := s.pluginRepoFn()
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		plg, err := plgRepo.LookupPluginByName(ctx, req.GetPluginName())
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		if plg == nil {
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "plugin with provided name not found")
		}
		pluginId = plg.GetPublicId()
	}
	h, err := toStoragePluginCatalog(ctx, projId, pluginId, item)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build catalog for creation"))
	}
	repo, err := s.pluginHostRepoFn()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	out, plg, err := repo.CreateCatalog(ctx, h)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create host catalog"))
	}
	if out == nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create host catalog but no error returned from repository.")
	}
	return out, toPluginInfo(plg), nil
}

func (s Service) createInRepo(ctx context.Context, projId string, req *pbs.CreateHostCatalogRequest) (hc host.Catalog, info *plugins.PluginInfo, err error) {
	var plg *plugins.PluginInfo
	switch subtypes.SubtypeFromType(domain, req.GetItem().GetType()) {
	case static.Subtype:
		hc, err = s.createStaticInRepo(ctx, projId, req.GetItem())
	default:
		hc, plg, err = s.createPluginInRepo(ctx, projId, req)
	}
	return hc, plg, err
}

func (s Service) updateStaticInRepo(ctx context.Context, projId, id string, mask []string, item *pb.HostCatalog) (*static.HostCatalog, error) {
	const op = "host_catalogs.(Service).updateStaticInRepo"
	h, err := toStorageStaticCatalog(ctx, projId, item)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build host catalog for update"))
	}
	version := item.GetVersion()
	h.PublicId = id
	dbMask := staticMaskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, rowsUpdated, err := repo.UpdateCatalog(ctx, h, version, dbMask)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update host catalog"))
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Host Catalog %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) updatePluginInRepo(ctx context.Context, projId, id string, mask []string, item *pb.HostCatalog) (*plugin.HostCatalog, *plugins.PluginInfo, error) {
	const op = "host_catalogs.(Service).updatePluginInRepo"
	h, err := toStoragePluginCatalog(ctx, projId, "", item)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build host catalog for update"))
	}
	version := item.GetVersion()
	h.PublicId = id
	dbMask := pluginMaskManager.Translate(mask, "attributes", "secrets")
	if len(dbMask) == 0 {
		return nil, nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}

	repo, err := s.pluginHostRepoFn()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	out, plg, rowsUpdated, err := repo.UpdateCatalog(ctx, h, version, dbMask)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update host catalog"))
	}
	if rowsUpdated == 0 {
		return nil, nil, handlers.NotFoundErrorf("Host Catalog %q doesn't exist or incorrect version provided.", id)
	}
	return out, toPluginInfo(plg), nil
}

func (s Service) updateInRepo(ctx context.Context, projId string, req *pbs.UpdateHostCatalogRequest) (hc host.Catalog, plg *plugins.PluginInfo, err error) {
	const op = "host_catalogs.(Service).updateInRepo"
	switch subtypes.SubtypeFromId(domain, req.GetId()) {
	case static.Subtype:
		hc, err = s.updateStaticInRepo(ctx, projId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	case plugin.Subtype:
		hc, plg, err = s.updatePluginInRepo(ctx, projId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	}
	return
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	const op = "host_catalogs.(Service).deleteFromRepo"
	rows := 0
	switch subtypes.SubtypeFromId(domain, id) {
	case static.Subtype:
		repo, err := s.staticRepoFn()
		if err != nil {
			return false, errors.Wrap(ctx, err, op)
		}
		rows, err = repo.DeleteCatalog(ctx, id)
		if err != nil {
			return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete host"))
		}
	case plugin.Subtype:
		repo, err := s.pluginHostRepoFn()
		if err != nil {
			return false, errors.Wrap(ctx, err, op)
		}
		rows, err = repo.DeleteCatalog(ctx, id)
		if err != nil {
			return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete host"))
		}
	}
	return rows > 0, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	res := auth.VerifyResults{}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.HostCatalog), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
		iamRepo, err := s.iamRepoFn()
		if err != nil {
			res.Error = err
			return res
		}
		scp, err := iamRepo.LookupScope(ctx, parentId)
		if err != nil {
			res.Error = err
			return res
		}
		if scp == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
	default:
		switch subtypes.SubtypeFromId(domain, id) {
		case static.Subtype:
			repo, err := s.staticRepoFn()
			if err != nil {
				res.Error = err
				return res
			}
			cat, err := repo.LookupCatalog(ctx, id)
			if err != nil {
				res.Error = err
				return res
			}
			if cat == nil {
				res.Error = handlers.NotFoundError()
				return res
			}
			parentId = cat.GetProjectId()
			opts = append(opts, auth.WithId(id))
		case plugin.Subtype:
			repo, err := s.pluginHostRepoFn()
			if err != nil {
				res.Error = err
				return res
			}
			cat, _, err := repo.LookupCatalog(ctx, id)
			if err != nil {
				res.Error = err
				return res
			}
			if cat == nil {
				res.Error = handlers.NotFoundError()
				return res
			}
			parentId = cat.GetProjectId()
			opts = append(opts, auth.WithId(id))
		}
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, opts...)
}

func toPluginInfo(plg *hostplugin.Plugin) *plugins.PluginInfo {
	if plg == nil {
		return nil
	}
	return &plugins.PluginInfo{
		Id:          plg.GetPublicId(),
		Name:        plg.GetName(),
		Description: plg.GetDescription(),
	}
}

func toProto(ctx context.Context, in host.Catalog, opt ...handlers.Option) (*pb.HostCatalog, error) {
	const op = "host_catalog_service.toProto"
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building auth method proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.HostCatalog{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.GetProjectId()
	}
	if outputFields.Has(globals.TypeField) {
		switch in.(type) {
		case *static.HostCatalog:
			out.Type = static.Subtype.String()
		case *plugin.HostCatalog:
			out.Type = plugin.Subtype.String()
		}
	}
	if outputFields.Has(globals.DescriptionField) && in.GetDescription() != "" {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if outputFields.Has(globals.NameField) && in.GetName() != "" {
		out.Name = wrapperspb.String(in.GetName())
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
	if outputFields.Has(globals.PluginField) {
		out.Plugin = opts.WithPlugin
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		out.AuthorizedCollectionActions = opts.WithAuthorizedCollectionActions
	}
	switch h := in.(type) {
	case *plugin.HostCatalog:
		if outputFields.Has(globals.PluginIdField) {
			out.PluginId = h.GetPluginId()
		}
		if outputFields.Has(globals.SecretsHmacField) {
			out.SecretsHmac = base58.Encode(h.GetSecretsHmac())
		}
		if outputFields.Has(globals.AttributesField) {
			attrs := &structpb.Struct{}
			err := proto.Unmarshal(h.Attributes, attrs)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			if len(attrs.GetFields()) > 0 {
				out.Attrs = &pb.HostCatalog_Attributes{
					Attributes: attrs,
				}
			}
		}
	}
	return &out, nil
}

func toStorageStaticCatalog(ctx context.Context, projectId string, item *pb.HostCatalog) (*static.HostCatalog, error) {
	const op = "host_catalog_service.toStorageStaticCatalog"
	var opts []static.Option
	if name := item.GetName(); name != nil {
		opts = append(opts, static.WithName(name.GetValue()))
	}
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, static.WithDescription(desc.GetValue()))
	}
	hc, err := static.NewHostCatalog(projectId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build host catalog"))
	}
	return hc, nil
}

func toStoragePluginCatalog(ctx context.Context, projectId, plgId string, item *pb.HostCatalog) (*plugin.HostCatalog, error) {
	const op = "host_catalog_service.toStoragePluginCatalog"
	var opts []plugin.Option
	if name := item.GetName(); name != nil {
		opts = append(opts, plugin.WithName(item.GetName().GetValue()))
	}
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, plugin.WithDescription(desc.GetValue()))
	}
	if attrs := item.GetAttributes(); attrs != nil {
		opts = append(opts, plugin.WithAttributes(attrs))
	}
	if secrets := item.GetSecrets(); secrets != nil {
		opts = append(opts, plugin.WithSecrets(secrets))
	}
	hc, err := plugin.NewHostCatalog(ctx, projectId, plgId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to build host set for creation"))
	}
	return hc, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
//   - The type asserted by the ID and/or field is known
//   - If relevant, the type derived from the id prefix matches what is claimed by the type field
func validateGetRequest(req *pbs.GetHostCatalogRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, static.HostCatalogPrefix, plugin.HostCatalogPrefix, plugin.PreviousHostCatalogPrefix)
}

func validateCreateRequest(req *pbs.CreateHostCatalogRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetScopeId()), scope.Project.Prefix()) {
			badFields[globals.ScopeIdField] = "This field must be a valid project scope id."
		}
		if req.GetItem().GetSecretsHmac() != "" {
			badFields[globals.SecretsHmacField] = "This is a read only field."
		}
		switch subtypes.SubtypeFromType(domain, req.GetItem().GetType()) {
		case static.Subtype:
		case plugin.Subtype:
			if req.GetItem().GetPlugin() != nil {
				badFields[globals.PluginField] = "This is a read only field."
			}
			if req.GetItem().GetPluginId() == "" && req.GetPluginName() == "" {
				badFields[globals.PluginIdField] = "This or plugin name is a required field."
				badFields[globals.PluginNameField] = "This or plugin id is a required field."
			}
			if req.GetItem().GetPluginId() != "" && req.GetPluginName() != "" {
				badFields[globals.PluginIdField] = "Can't set the plugin name field along with this field."
				badFields[globals.PluginNameField] = "Can't set the plugin id field along with this field."
			}
		default:
			badFields[globals.TypeField] = fmt.Sprintf("This is a required field and must be either %q or %q.", static.Subtype.String(), plugin.Subtype.String())
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateHostCatalogRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetSecretsHmac() != "" {
			badFields[globals.SecretsHmacField] = "This is a read only field."
		}
		switch subtypes.SubtypeFromId(domain, req.GetId()) {
		case static.Subtype:
			if req.GetItem().GetType() != "" && subtypes.SubtypeFromType(domain, req.GetItem().GetType()) != static.Subtype {
				badFields[globals.TypeField] = "Cannot modify resource type."
			}
			if req.GetItem().GetPlugin() != nil {
				badFields[globals.PluginField] = "This field is unused for this type of host catalog."
			}
		case plugin.Subtype:
			if req.GetItem().GetType() != "" && subtypes.SubtypeFromType(domain, req.GetItem().GetType()) != plugin.Subtype {
				badFields[globals.TypeField] = "Cannot modify resource type."
			}
			if req.GetItem().GetPlugin() != nil {
				badFields[globals.PluginField] = "This is a read only field."
			}
		}
		return badFields
	}, static.HostCatalogPrefix, plugin.HostCatalogPrefix, plugin.PreviousHostCatalogPrefix)
}

func validateDeleteRequest(req *pbs.DeleteHostCatalogRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, static.HostCatalogPrefix, plugin.HostCatalogPrefix, plugin.PreviousHostCatalogPrefix)
}

func validateListRequest(req *pbs.ListHostCatalogsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) &&
		!req.GetRecursive() {
		badFields[globals.ScopeIdField] = "This field must be a valid project scope ID or the list operation must be recursive."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields[globals.FilterField] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}
