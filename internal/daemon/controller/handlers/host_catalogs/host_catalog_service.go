// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	pluginstore "github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
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
	IdActions = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
	)

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.Create,
		action.List,
	)

	collectionTypeMap = map[globals.Subtype]map[resource.Type]action.ActionSet{
		static.Subtype: {
			resource.HostSet: host_sets.CollectionActions,
			resource.Host:    hosts.CollectionActions,
		},
		hostplugin.Subtype: {
			resource.HostSet: host_sets.CollectionActions,
			resource.Host: action.NewActionSet(
				action.List,
			),
		},
	}

	additionalResourceGrants = []resource.Type{
		resource.HostSet,
		resource.Host,
	}

	validateWorkerFilterFn = validateWorkerFilterUnsupported
	workerFilterToProto    = false
)

func validateWorkerFilterUnsupported(_ string) error {
	return fmt.Errorf("Worker filter on host catalogs is an Enterprise-only feature")
}

const domain = "host"

func init() {
	var err error
	if staticMaskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.HostCatalog{}, &store.UnimplementedCatalogFields{}},
		handlers.MaskSource{&pb.HostCatalog{}},
	); err != nil {
		panic(err)
	}
	if pluginMaskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&pluginstore.HostCatalog{}},
		handlers.MaskSource{&pb.HostCatalog{}},
	); err != nil {
		panic(err)
	}

	// TODO: refactor to remove idActionsMap and CollectionActions package variables
	action.RegisterResource(resource.HostCatalog, IdActions, CollectionActions)
}

type Service struct {
	pbs.UnsafeHostCatalogServiceServer

	staticRepoFn      common.StaticRepoFactory
	pluginHostRepoFn  common.PluginHostRepoFactory
	pluginRepoFn      common.PluginRepoFactory
	iamRepoFn         common.IamRepoFactory
	hostCatalogRepoFn common.HostCatalogRepoFactory
	maxPageSize       uint
}

var _ pbs.HostCatalogServiceServer = (*Service)(nil)

// NewService returns a host catalog Service which handles host catalog related requests to boundary and uses the provided
// repositories for storage and retrieval.
func NewService(
	ctx context.Context,
	repoFn common.StaticRepoFactory,
	pluginHostRepoFn common.PluginHostRepoFactory,
	hostPluginRepoFn common.PluginRepoFactory,
	iamRepoFn common.IamRepoFactory,
	hostCatalogRepoFn common.HostCatalogRepoFactory,
	maxPageSize uint,
) (Service, error) {
	const op = "host_catalogs.NewService"
	if repoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing static repository")
	}
	if pluginHostRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing plugin host repository")
	}
	if hostPluginRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing host plugin repository")
	}
	if iamRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	if hostCatalogRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing host catalog repo")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return Service{
		staticRepoFn:      repoFn,
		pluginHostRepoFn:  pluginHostRepoFn,
		pluginRepoFn:      hostPluginRepoFn,
		iamRepoFn:         iamRepoFn,
		hostCatalogRepoFn: hostCatalogRepoFn,
		maxPageSize:       maxPageSize,
	}, nil
}

func (s Service) ListHostCatalogs(ctx context.Context, req *pbs.ListHostCatalogsRequest) (*pbs.ListHostCatalogsResponse, error) {
	const op = "host_catalogs.(Service).ListHostCatalogs"
	if err := validateListRequest(ctx, req); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List, req.GetRecursive())
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
		return nil, errors.Wrap(ctx, err, op)
	}
	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}

	var filterItemFn func(ctx context.Context, item host.Catalog, plgs map[string]*plugin.Plugin) (bool, error)
	switch {
	case req.GetFilter() != "":
		// Only use a filter if we need to
		filter, err := handlers.NewFilter(ctx, req.GetFilter())
		if err != nil {
			return nil, err
		}
		// TODO: replace the need for this function with some way to convert the `filter`
		// to a domain type. This would allow filtering to happen in the domain, and we could
		// remove this callback altogether.
		filterItemFn = func(ctx context.Context, item host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
			outputOpts, ok, err := newOutputOpts(ctx, item, authResults, scopeInfoMap, plgs)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
			pbItem, err := toProto(ctx, item, outputOpts...)
			if err != nil {
				return false, err
			}

			// This comes last so that we can use item fields in the filter after
			// the allowed fields are populated above
			filterable, err := subtypes.Filterable(ctx, pbItem)
			if err != nil {
				return false, err
			}
			return filter.Match(filterable), nil
		}
	default:
		filterItemFn = func(ctx context.Context, item host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
	}
	repo, err := s.hostCatalogRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	grantsHash, err := authResults.GrantsHash(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var listResp *pagination.ListResponse[host.Catalog]
	var plgs map[string]*plugin.Plugin
	var sortBy string
	if req.GetListToken() == "" {
		sortBy = "created_time"
		listResp, plgs, err = host.ListCatalogs(ctx, grantsHash, pageSize, filterItemFn, repo, scopeIds)
		if err != nil {
			return nil, err
		}
	} else {

		listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.HostCatalog, grantsHash)
		if err != nil {
			return nil, err
		}
		switch st := listToken.Subtype.(type) {
		case *listtoken.PaginationToken:
			sortBy = "created_time"
			listResp, plgs, err = host.ListCatalogsPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.StartRefreshToken:
			sortBy = "updated_time"
			listResp, plgs, err = host.ListCatalogsRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.RefreshToken:
			sortBy = "updated_time"
			listResp, plgs, err = host.ListCatalogsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		default:
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
		}
	}

	finalItems := make([]*pb.HostCatalog, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		outputOpts, ok, err := newOutputOpts(ctx, item, authResults, scopeInfoMap, plgs)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if !ok {
			continue
		}
		item, err := toProto(ctx, item, outputOpts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		finalItems = append(finalItems, item)
	}
	respType := "delta"
	if listResp.CompleteListing {
		respType = "complete"
	}
	resp := &pbs.ListHostCatalogsResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}

	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_HOST_CATALOG)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// GetHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) GetHostCatalog(ctx context.Context, req *pbs.GetHostCatalogRequest) (*pbs.GetHostCatalogResponse, error) {
	const op = "host_catalogs.(Service).GetostCatalog"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hc.GetPublicId(), IdActions).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		var subtype globals.Subtype
		switch hc.(type) {
		case *static.HostCatalog:
			subtype = static.Subtype
		case *hostplugin.HostCatalog:
			subtype = hostplugin.Subtype
		}
		if subtype != "" {
			collectionActions, err := auth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap[subtype], authResults.Scope, hc.GetPublicId())
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
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hc.GetPublicId(), IdActions).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		var subtype globals.Subtype
		switch hc.(type) {
		case *static.HostCatalog:
			subtype = static.Subtype
		case *hostplugin.HostCatalog:
			subtype = hostplugin.Subtype
		}
		if subtype != "" {
			collectionActions, err := auth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap[subtype], authResults.Scope, hc.GetPublicId())
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
	authResults := s.authResult(ctx, req.GetId(), action.Update, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
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
		var subtype globals.Subtype
		switch hc.(type) {
		case *static.HostCatalog:
			subtype = static.Subtype
		case *hostplugin.HostCatalog:
			subtype = hostplugin.Subtype
		}
		if subtype != "" {
			collectionActions, err := auth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap[subtype], authResults.Scope, hc.GetPublicId())
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
	authResults := s.authResult(ctx, req.GetId(), action.Delete, false)
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
	switch globals.ResourceInfoFromPrefix(id).Subtype {
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
	case hostplugin.Subtype:
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

func (s Service) createPluginInRepo(ctx context.Context, projId string, req *pbs.CreateHostCatalogRequest) (*hostplugin.HostCatalog, *plugins.PluginInfo, error) {
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
	switch req.GetItem().GetType() {
	case static.Subtype.String():
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

func (s Service) updatePluginInRepo(ctx context.Context, projId, id string, mask []string, item *pb.HostCatalog) (*hostplugin.HostCatalog, *plugins.PluginInfo, error) {
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
	switch globals.ResourceInfoFromPrefix(req.GetId()).Subtype {
	case static.Subtype:
		hc, err = s.updateStaticInRepo(ctx, projId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	case hostplugin.Subtype:
		hc, plg, err = s.updatePluginInRepo(ctx, projId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	}
	return hc, plg, err
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	const op = "host_catalogs.(Service).deleteFromRepo"
	rows := 0
	switch globals.ResourceInfoFromPrefix(id).Subtype {
	case static.Subtype:
		repo, err := s.staticRepoFn()
		if err != nil {
			return false, errors.Wrap(ctx, err, op)
		}
		rows, err = repo.DeleteCatalog(ctx, id)
		if err != nil {
			return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete host"))
		}
	case hostplugin.Subtype:
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

func (s Service) authResult(ctx context.Context, id string, a action.Type, isRecursive bool) auth.VerifyResults {
	res := auth.VerifyResults{}

	var parentId string
	opts := []auth.Option{auth.WithAction(a), auth.WithRecursive(isRecursive), auth.WithFetchAdditionalResourceGrants(additionalResourceGrants...)}
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
		switch globals.ResourceInfoFromPrefix(id).Subtype {
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
		case hostplugin.Subtype:
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
	return auth.Verify(ctx, resource.HostCatalog, opts...)
}

func toPluginInfo(plg *plugin.Plugin) *plugins.PluginInfo {
	if plg == nil {
		return nil
	}
	return &plugins.PluginInfo{
		Id:          plg.GetPublicId(),
		Name:        plg.GetName(),
		Description: plg.GetDescription(),
	}
}

func newOutputOpts(
	ctx context.Context,
	item host.Catalog,
	authResults auth.VerifyResults,
	scopeInfoMap map[string]*scopes.ScopeInfo,
	pluginMap map[string]*plugin.Plugin,
) ([]handlers.Option, bool, error) {
	res := perms.Resource{
		Type:          resource.HostCatalog,
		Id:            item.GetPublicId(),
		ScopeId:       item.GetProjectId(),
		ParentScopeId: scopeInfoMap[item.GetProjectId()].GetParentScopeId(),
	}
	authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res)).Strings()
	if len(authorizedActions) == 0 {
		return nil, false, nil
	}

	outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(scopeInfoMap[item.GetProjectId()]))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		var subtype globals.Subtype
		switch item.(type) {
		case *static.HostCatalog:
			subtype = static.Subtype
		case *hostplugin.HostCatalog:
			subtype = hostplugin.Subtype
		}
		if subtype != "" {
			collectionActions, err := auth.CalculateAuthorizedCollectionActions(ctx, authResults, collectionTypeMap[subtype], authResults.Scope, item.GetPublicId())
			if err != nil {
				return nil, false, err
			}
			outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
		}
	}
	if pluginMap != nil {
		if hc, ok := item.(*hostplugin.HostCatalog); ok {
			if plg, ok := pluginMap[hc.GetPluginId()]; ok {
				outputOpts = append(outputOpts, handlers.WithPlugin(toPluginInfo(plg)))
			}
		}
	}

	return outputOpts, true, nil
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
		case *hostplugin.HostCatalog:
			out.Type = hostplugin.Subtype.String()
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
	case *hostplugin.HostCatalog:
		if outputFields.Has(globals.PluginIdField) {
			out.PluginId = h.GetPluginId()
		}
		if outputFields.Has(globals.SecretsHmacField) {
			out.SecretsHmac = base58.Encode(h.GetSecretsHmac())
		}
		if outputFields.Has(globals.WorkerFilterField) && h.GetWorkerFilter() != "" {
			if workerFilterToProto {
				out.WorkerFilter = wrapperspb.String(h.GetWorkerFilter())
			}
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
	hc, err := static.NewHostCatalog(ctx, projectId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build host catalog"))
	}
	return hc, nil
}

func toStoragePluginCatalog(ctx context.Context, projectId, plgId string, item *pb.HostCatalog) (*hostplugin.HostCatalog, error) {
	const op = "host_catalog_service.toStoragePluginCatalog"
	var opts []hostplugin.Option
	if name := item.GetName(); name != nil {
		opts = append(opts, hostplugin.WithName(item.GetName().GetValue()))
	}
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, hostplugin.WithDescription(desc.GetValue()))
	}
	if attrs := item.GetAttributes(); attrs != nil {
		opts = append(opts, hostplugin.WithAttributes(attrs))
	}
	if secrets := item.GetSecrets(); secrets != nil {
		opts = append(opts, hostplugin.WithSecrets(secrets))
	}
	if workerFilter := item.GetWorkerFilter(); workerFilter != nil {
		opts = append(opts, hostplugin.WithWorkerFilter(workerFilter.GetValue()))
	}
	hc, err := hostplugin.NewHostCatalog(ctx, projectId, plgId, opts...)
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
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, globals.StaticHostCatalogPrefix, globals.PluginHostCatalogPrefix, globals.PluginHostCatalogPreviousPrefix)
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
		switch req.GetItem().GetType() {
		case static.Subtype.String():
		case hostplugin.Subtype.String():
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
			if req.GetItem().GetWorkerFilter() != nil {
				err := validateWorkerFilterFn(req.GetItem().GetWorkerFilter().GetValue())
				if err != nil {
					badFields[globals.WorkerFilterField] = err.Error()
				}
			}
		default:
			badFields[globals.TypeField] = fmt.Sprintf("This is a required field and must be either %q or %q.", static.Subtype.String(), hostplugin.Subtype.String())
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
		switch globals.ResourceInfoFromPrefix(req.GetId()).Subtype {
		case static.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != static.Subtype.String() {
				badFields[globals.TypeField] = "Cannot modify resource type."
			}
			if req.GetItem().GetPlugin() != nil {
				badFields[globals.PluginField] = "This field is unused for this type of host catalog."
			}
		case hostplugin.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != hostplugin.Subtype.String() {
				badFields[globals.TypeField] = "Cannot modify resource type."
			}
			if req.GetItem().GetPlugin() != nil {
				badFields[globals.PluginField] = "This is a read only field."
			}
			if req.GetItem().GetWorkerFilter() != nil {
				err := validateWorkerFilterFn(req.GetItem().GetWorkerFilter().GetValue())
				if err != nil {
					badFields[globals.WorkerFilterField] = err.Error()
				}
			}
		}
		return badFields
	}, globals.StaticHostCatalogPrefix, globals.PluginHostCatalogPrefix, globals.PluginHostCatalogPreviousPrefix)
}

func validateDeleteRequest(req *pbs.DeleteHostCatalogRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, globals.StaticHostCatalogPrefix, globals.PluginHostCatalogPrefix, globals.PluginHostCatalogPreviousPrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListHostCatalogsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) &&
		!req.GetRecursive() {
		badFields[globals.ScopeIdField] = "This field must be a valid project scope ID or the list operation must be recursive."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields[globals.FilterField] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}
