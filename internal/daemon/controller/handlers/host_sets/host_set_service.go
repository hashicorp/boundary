// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host_sets

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	plugstore "github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/host/static"
	staticstore "github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/libs/endpoint"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager = map[globals.Subtype]handlers.MaskManager{}

	// IdActions contains the set of actions that can be performed on
	// individual resources
	idActionsTypeMap = map[globals.Subtype]action.ActionSet{
		static.Subtype: action.NewActionSet(
			action.NoOp,
			action.Read,
			action.Update,
			action.Delete,
			action.AddHosts,
			action.SetHosts,
			action.RemoveHosts,
		),
		hostplugin.Subtype: action.NewActionSet(
			action.NoOp,
			action.Read,
			action.Update,
			action.Delete,
		),
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.Create,
		action.List,
	)
)

func init() {
	var err error
	if maskManager[static.Subtype], err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&staticstore.HostSet{}, &staticstore.UnimplementedSetFields{}},
		handlers.MaskSource{&pb.HostSet{}},
	); err != nil {
		panic(err)
	}
	if maskManager[hostplugin.Subtype], err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&plugstore.HostSet{}},
		handlers.MaskSource{&pb.HostSet{}},
	); err != nil {
		panic(err)
	}

	// TODO: refactor to remove idActionsMap and CollectionActions package variables
	action.RegisterResource(resource.HostSet, action.Union(maps.Values(idActionsTypeMap)...), CollectionActions)
}

type Service struct {
	pbs.UnsafeHostSetServiceServer

	staticRepoFn common.StaticRepoFactory
	pluginRepoFn common.PluginHostRepoFactory
	maxPageSize  uint
}

var _ pbs.HostSetServiceServer = (*Service)(nil)

// NewService returns a host set Service which handles host set related requests to boundary and uses the provided
// repositories for storage and retrieval.
func NewService(ctx context.Context, staticRepoFn common.StaticRepoFactory, pluginRepoFn common.PluginHostRepoFactory, maxPageSize uint) (Service, error) {
	const op = "host_sets.NewService"
	if staticRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing static repository")
	}
	if pluginRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing hostplugin repository")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return Service{staticRepoFn: staticRepoFn, pluginRepoFn: pluginRepoFn, maxPageSize: maxPageSize}, nil
}

func (s Service) ListHostSets(ctx context.Context, req *pbs.ListHostSetsRequest) (*pbs.ListHostSetsResponse, error) {
	return s.ListHostSetsWithOptions(ctx, req)
}

func (s Service) ListHostSetsWithOptions(ctx context.Context, req *pbs.ListHostSetsRequest, opt ...host.Option) (*pbs.ListHostSetsResponse, error) {
	const op = "host_sets.(Service).ListHostSets"
	if err := validateListRequest(ctx, req); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetHostCatalogId(), action.List, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}
	var filterItemFn func(ctx context.Context, item host.Set, plg *plugin.Plugin) (bool, error)
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
		filterItemFn = func(ctx context.Context, item host.Set, plg *plugin.Plugin) (bool, error) {
			outputOpts, ok := newOutputOpts(ctx, item, toPluginInfo(plg), authResults)
			if !ok {
				return false, nil
			}
			pbItem, err := toProto(ctx, item, nil, outputOpts...)
			if err != nil {
				return false, err
			}

			filterable, err := subtypes.Filterable(ctx, pbItem)
			if err != nil {
				return false, err
			}
			return filter.Match(filterable), nil
		}
	default:
		filterItemFn = func(ctx context.Context, item host.Set, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
	}

	grantsHash, err := authResults.GrantsHash(ctx)
	if err != nil {
		return nil, err
	}

	var listResp *pagination.ListResponse[host.Set]
	var sortBy string
	var hsplg *plugin.Plugin
	switch globals.ResourceInfoFromPrefix(req.GetHostCatalogId()).Subtype {
	case static.Subtype:
		// Wrap the filter item func that takes a plugin, since the static host set
		// domain does not use a plugin.
		staticFilterItemFn := func(ctx context.Context, item host.Set) (bool, error) {
			return filterItemFn(ctx, item, nil)
		}
		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if req.GetListToken() == "" {
			sortBy = "created_time"
			listResp, err = static.ListHostSets(ctx, grantsHash, pageSize, staticFilterItemFn, repo, req.GetHostCatalogId())
			if err != nil {
				return nil, err
			}
		} else {
			listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.HostSet, grantsHash)
			if err != nil {
				return nil, err
			}
			switch st := listToken.Subtype.(type) {
			case *listtoken.PaginationToken:
				sortBy = "created_time"
				listResp, err = static.ListHostSetsPage(ctx, grantsHash, pageSize, staticFilterItemFn, listToken, repo, req.GetHostCatalogId())
				if err != nil {
					return nil, err
				}
			case *listtoken.StartRefreshToken:
				sortBy = "updated_time"
				listResp, err = static.ListHostSetsRefresh(ctx, grantsHash, pageSize, staticFilterItemFn, listToken, repo, req.GetHostCatalogId())
				if err != nil {
					return nil, err
				}
			case *listtoken.RefreshToken:
				sortBy = "updated_time"
				listResp, err = static.ListHostSetsRefreshPage(ctx, grantsHash, pageSize, staticFilterItemFn, listToken, repo, req.GetHostCatalogId())
				if err != nil {
					return nil, err
				}
			default:
				return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
			}
		}
	case hostplugin.Subtype:
		repo, err := s.pluginRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if req.GetListToken() == "" {
			sortBy = "created_time"
			listResp, hsplg, err = hostplugin.ListHostSets(ctx, grantsHash, pageSize, filterItemFn, repo, req.GetHostCatalogId())
			if err != nil {
				return nil, err
			}
		} else {
			listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.HostSet, grantsHash)
			if err != nil {
				return nil, err
			}
			switch st := listToken.Subtype.(type) {
			case *listtoken.PaginationToken:
				sortBy = "created_time"
				listResp, hsplg, err = hostplugin.ListHostSetsPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, req.GetHostCatalogId())
				if err != nil {
					return nil, err
				}
			case *listtoken.StartRefreshToken:
				sortBy = "updated_time"
				listResp, hsplg, err = hostplugin.ListHostSetsRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, req.GetHostCatalogId())
				if err != nil {
					return nil, err
				}
			case *listtoken.RefreshToken:
				sortBy = "updated_time"
				listResp, hsplg, err = hostplugin.ListHostSetsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, req.GetHostCatalogId())
				if err != nil {
					return nil, err
				}
			default:
				return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
			}
		}
	}

	plg := toPluginInfo(hsplg)
	finalItems := make([]*pb.HostSet, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		outputOpts, ok := newOutputOpts(ctx, item, plg, authResults)
		if !ok {
			continue
		}
		pbItem, err := toProto(ctx, item, nil, outputOpts...)
		if err != nil {
			continue
		}
		finalItems = append(finalItems, pbItem)
	}
	respType := "delta"
	if listResp.CompleteListing {
		respType = "complete"
	}
	resp := &pbs.ListHostSetsResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}

	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_HOST_SET)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// GetHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) GetHostSet(ctx context.Context, req *pbs.GetHostSetRequest) (*pbs.GetHostSetResponse, error) {
	const op = "host_sets.(Service).GetHostSet"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Read, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hs, hosts, plg, err := s.getFromRepo(ctx, req.GetId())
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
		idActions := idActionsTypeMap[globals.ResourceInfoFromPrefix(req.GetId()).Subtype]
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hs.GetPublicId(), idActions).Strings()))
	}
	if plg != nil {
		outputOpts = append(outputOpts, handlers.WithPlugin(plg))
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

	if err := validateCreateRequest(ctx, req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetItem().GetHostCatalogId(), action.Create, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hs, plg, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem().GetHostCatalogId(), req.GetItem())
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
		idActions := idActionsTypeMap[globals.ResourceInfoFromPrefix(req.GetItem().GetHostCatalogId()).Subtype]
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hs.GetPublicId(), idActions).Strings()))
	}
	if plg != nil {
		outputOpts = append(outputOpts, handlers.WithPlugin(plg))
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

	if err := validateUpdateRequest(ctx, req); err != nil {
		return nil, err
	}
	cat, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Update, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hs, hosts, plg, err := s.updateInRepo(ctx, authResults.Scope.GetId(), cat.GetPublicId(), req)
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
		idActions := idActionsTypeMap[globals.ResourceInfoFromPrefix(req.GetId()).Subtype]
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hs.GetPublicId(), idActions).Strings()))
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
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Delete, false)
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
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.AddHosts, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		idActions := idActionsTypeMap[globals.ResourceInfoFromPrefix(req.GetId()).Subtype]
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hs.GetPublicId(), idActions).Strings()))
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
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.SetHosts, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		idActions := idActionsTypeMap[globals.ResourceInfoFromPrefix(req.GetId()).Subtype]
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hs.GetPublicId(), idActions).Strings()))
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
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.RemoveHosts, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		idActions := idActionsTypeMap[globals.ResourceInfoFromPrefix(req.GetId()).Subtype]
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, hs.GetPublicId(), idActions).Strings()))
	}

	item, err := toProto(ctx, hs, hosts, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveHostSetHostsResponse{Item: item}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (host.Set, []host.Host, *plugins.PluginInfo, error) {
	var hs host.Set
	var hl []host.Host
	var plg *plugins.PluginInfo
	switch globals.ResourceInfoFromPrefix(id).Subtype {
	case static.Subtype:
		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, nil, nil, err
		}
		hset, hosts, err := repo.LookupSet(ctx, id)
		if err != nil {
			return nil, nil, nil, err
		}
		if hset == nil {
			return nil, nil, nil, handlers.NotFoundErrorf("Host Set %q doesn't exist.", id)
		}
		for _, h := range hosts {
			hl = append(hl, h)
		}
		hs = hset
	case hostplugin.Subtype:
		repo, err := s.pluginRepoFn()
		if err != nil {
			return nil, nil, nil, err
		}
		hset, hsplg, err := repo.LookupSet(ctx, id)
		if err != nil {
			return nil, nil, nil, err
		}
		if hset == nil {
			return nil, nil, nil, handlers.NotFoundErrorf("Host Set %q doesn't exist.", id)
		}
		hs = hset
		plg = toPluginInfo(hsplg)
		for _, h := range hset.HostIds {
			hl = append(hl, &hostplugin.Host{
				Host: &plugstore.Host{
					PublicId:  h,
					CatalogId: hset.CatalogId,
				},
			})
		}
	}
	return hs, hl, plg, nil
}

func (s Service) createInRepo(ctx context.Context, projectId, catalogId string, item *pb.HostSet) (host.Set, *plugins.PluginInfo, error) {
	const op = "host_sets.(Service).createInRepo"
	if item == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing item")
	}
	var hSet host.Set
	var plg *plugins.PluginInfo
	switch globals.ResourceInfoFromPrefix(catalogId).Subtype {
	case static.Subtype:
		h, err := toStorageStaticSet(ctx, catalogId, item)
		if err != nil {
			return nil, nil, err
		}
		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, nil, err
		}
		out, err := repo.CreateSet(ctx, projectId, h)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create host set"))
		}
		if out == nil {
			return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create host set but no error returned from repository.")
		}
		hSet = out
	case hostplugin.Subtype:
		h, err := toStoragePluginSet(ctx, catalogId, item)
		if err != nil {
			return nil, nil, err
		}
		repo, err := s.pluginRepoFn()
		if err != nil {
			return nil, nil, err
		}
		out, hsplg, err := repo.CreateSet(ctx, projectId, h)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create host set"))
		}
		if out == nil {
			return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create host set but no error returned from repository.")
		}
		hSet = out
		plg = toPluginInfo(hsplg)
	default:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "unrecognized catalog type")
	}
	return hSet, plg, nil
}

func (s Service) updateStaticInRepo(ctx context.Context, projectId, catalogId string, req *pbs.UpdateHostSetRequest) (host.Set, []host.Host, error) {
	const op = "host_sets.(Service).updateStaticInRepo"
	item := req.GetItem()
	h, err := toStorageStaticSet(ctx, catalogId, item)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to build host set for update"))
	}
	h.PublicId = req.GetId()
	dbMask := maskManager[static.Subtype].Translate(req.GetUpdateMask().GetPaths())
	if len(dbMask) == 0 {
		return nil, nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, nil, err
	}
	out, m, rowsUpdated, err := repo.UpdateSet(ctx, projectId, h, item.GetVersion(), dbMask)
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

func (s Service) updatePluginInRepo(ctx context.Context, projectId string, req *pbs.UpdateHostSetRequest) (host.Set, []host.Host, *plugins.PluginInfo, error) {
	const op = "host_sets.(Service).updatePluginInRepo"
	item := req.GetItem()
	h, err := toStoragePluginSet(ctx, "", item)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to build host set for update"))
	}
	h.PublicId = req.GetId()
	dbMask := maskManager[hostplugin.Subtype].Translate(req.GetUpdateMask().GetPaths(), "attributes")
	if len(dbMask) == 0 {
		return nil, nil, nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.pluginRepoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	out, hosts, plg, rowsUpdated, err := repo.UpdateSet(ctx, projectId, h, item.GetVersion(), dbMask)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update host set"))
	}
	if rowsUpdated == 0 {
		return nil, nil, nil, handlers.NotFoundErrorf("Host Set %q doesn't exist or incorrect version provided.", req.GetId())
	}
	var hl []host.Host
	for _, h := range hosts {
		hl = append(hl, h)
	}
	return out, hl, toPluginInfo(plg), nil
}

func (s Service) updateInRepo(ctx context.Context, projectId, catalogId string, req *pbs.UpdateHostSetRequest) (hs host.Set, hosts []host.Host, plg *plugins.PluginInfo, err error) {
	const op = "host_sets.(Service).updateInRepo"
	switch globals.ResourceInfoFromPrefix(req.GetId()).Subtype {
	case static.Subtype:
		hs, hosts, err = s.updateStaticInRepo(ctx, projectId, catalogId, req)
	case hostplugin.Subtype:
		hs, hosts, plg, err = s.updatePluginInRepo(ctx, projectId, req)
	}
	return hs, hosts, plg, err
}

func (s Service) deleteFromRepo(ctx context.Context, projectId, id string) (bool, error) {
	const op = "host_sets.(Service).deleteFromRepo"
	rows := 0
	switch globals.ResourceInfoFromPrefix(id).Subtype {
	case static.Subtype:
		repo, err := s.staticRepoFn()
		if err != nil {
			return false, err
		}
		rows, err = repo.DeleteSet(ctx, projectId, id)
		if err != nil {
			return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete host"))
		}
	case hostplugin.Subtype:
		repo, err := s.pluginRepoFn()
		if err != nil {
			return false, err
		}
		rows, err = repo.DeleteSet(ctx, projectId, id)
		if err != nil {
			return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete host"))
		}
	}
	return rows > 0, nil
}

func newOutputOpts(ctx context.Context, item host.Set, plg *plugins.PluginInfo, authResults auth.VerifyResults) ([]handlers.Option, bool) {
	res := perms.Resource{
		ScopeId:       authResults.Scope.Id,
		ParentScopeId: authResults.Scope.ParentScopeId,
		Id:            item.GetPublicId(),
		Type:          resource.HostSet,
		Pin:           item.GetCatalogId(),
	}
	res.Id = item.GetPublicId()
	idActions := idActionsTypeMap[globals.ResourceInfoFromPrefix(item.GetPublicId()).Subtype]
	authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), idActions, auth.WithResource(&res)).Strings()
	if len(authorizedActions) == 0 {
		return nil, false
	}

	outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
	}
	if plg != nil {
		outputOpts = append(outputOpts, handlers.WithPlugin(plg))
	}
	return outputOpts, true
}

func (s Service) addInRepo(ctx context.Context, projectId, setId string, hostIds []string, version uint32) (*static.HostSet, []host.Host, error) {
	const op = "host_sets.(Service).addInRepo"
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, nil, err
	}
	_, err = repo.AddSetMembers(ctx, projectId, setId, version, strutil.RemoveDuplicates(hostIds, false))
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

func (s Service) setInRepo(ctx context.Context, projectId, setId string, hostIds []string, version uint32) (*static.HostSet, []host.Host, error) {
	const op = "host_sets.(Service).setInRepo"
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	_, _, err = repo.SetSetMembers(ctx, projectId, setId, version, strutil.RemoveDuplicates(hostIds, false))
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

func (s Service) removeInRepo(ctx context.Context, projectId, setId string, hostIds []string, version uint32) (*static.HostSet, []host.Host, error) {
	const op = "host_sets.(Service).removeInRepo"
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	_, err = repo.DeleteSetMembers(ctx, projectId, setId, version, strutil.RemoveDuplicates(hostIds, false))
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

func (s Service) parentAndAuthResult(ctx context.Context, id string, a action.Type, isRecursive bool) (host.Catalog, auth.VerifyResults) {
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
	opts := []auth.Option{auth.WithAction(a), auth.WithRecursive(isRecursive)}
	switch a {
	case action.List, action.Create:
		parentId = id
	default:
		var set host.Set
		switch globals.ResourceInfoFromPrefix(id).Subtype {
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
		case hostplugin.Subtype:
			ps, _, err := pluginRepo.LookupSet(ctx, id)
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
	switch globals.ResourceInfoFromPrefix(id).Subtype {
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
	case hostplugin.Subtype:
		pc, _, err := pluginRepo.LookupCatalog(ctx, parentId)
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
	opts = append(opts, auth.WithScopeId(cat.GetProjectId()), auth.WithPin(parentId))
	return cat, auth.Verify(ctx, resource.HostSet, opts...)
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
		switch in.(type) {
		case *static.HostSet:
			out.Type = static.Subtype.String()
		case *hostplugin.HostSet:
			out.Type = hostplugin.Subtype.String()
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
	if outputFields.Has(globals.PluginField) {
		out.Plugin = opts.WithPlugin
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
	}
	if outputFields.Has(globals.HostIdsField) {
		for _, h := range hosts {
			out.HostIds = append(out.HostIds, h.GetPublicId())
		}
	}

	switch h := in.(type) {
	case *hostplugin.HostSet:
		if outputFields.Has(globals.PreferredEndpointsField) {
			out.PreferredEndpoints = h.PreferredEndpoints
		}
		if outputFields.Has(globals.SyncIntervalSecondsField) && h.GetSyncIntervalSeconds() != 0 {
			out.SyncIntervalSeconds = &wrapperspb.Int32Value{Value: h.GetSyncIntervalSeconds()}
		}
		if outputFields.Has(globals.AttributesField) {
			attrs := &structpb.Struct{}
			err := proto.Unmarshal(h.Attributes, attrs)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			if len(attrs.GetFields()) > 0 {
				out.Attrs = &pb.HostSet_Attributes{
					Attributes: attrs,
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
	hs, err := static.NewHostSet(ctx, catalogId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to build host set for creation"))
	}
	return hs, nil
}

func toStoragePluginSet(ctx context.Context, catalogId string, item *pb.HostSet) (*hostplugin.HostSet, error) {
	const op = "host_set_service.toStoragePluginSet"
	var opts []hostplugin.Option
	if item.GetName() != nil {
		opts = append(opts, hostplugin.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, hostplugin.WithDescription(item.GetDescription().GetValue()))
	}
	if item.GetAttributes() != nil {
		opts = append(opts, hostplugin.WithAttributes(item.GetAttributes()))
	}
	if item.GetPreferredEndpoints() != nil {
		opts = append(opts, hostplugin.WithPreferredEndpoints(item.GetPreferredEndpoints()))
	}
	if item.GetSyncIntervalSeconds() != nil {
		opts = append(opts, hostplugin.WithSyncIntervalSeconds(item.GetSyncIntervalSeconds().GetValue()))
	}
	hs, err := hostplugin.NewHostSet(ctx, catalogId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to build host set for creation"))
	}
	return hs, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
//   - The type asserted by the ID and/or field is known
//   - If relevant, the type derived from the id prefix matches what is claimed by the type field
func validateGetRequest(req *pbs.GetHostSetRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, globals.StaticHostSetPrefix, globals.PluginHostSetPrefix, globals.PluginHostSetPreviousPrefix)
}

func validateCreateRequest(ctx context.Context, req *pbs.CreateHostSetRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetHostCatalogId()), globals.StaticHostCatalogPrefix, globals.PluginHostCatalogPrefix, globals.PluginHostCatalogPreviousPrefix) {
			badFields[globals.HostCatalogIdField] = "The field is incorrectly formatted."
		}
		if len(req.GetItem().GetPreferredEndpoints()) > 0 {
			_, err := endpoint.NewPreferencer(ctx, endpoint.WithPreferenceOrder(req.GetItem().GetPreferredEndpoints()))
			if err != nil {
				badFields[globals.PreferredEndpointsField] = fmt.Errorf("Error parsing preferred endpoints: %w.", err).Error()
			}
		}
		switch globals.ResourceInfoFromPrefix(req.GetItem().GetHostCatalogId()).Subtype {
		case static.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != static.Subtype.String() {
				badFields[globals.TypeField] = "Doesn't match the parent resource's type."
			}
			if len(req.GetItem().PreferredEndpoints) > 0 {
				badFields[globals.PreferredEndpointsField] = "This field is not yet supported for static host sets."
			}
		case hostplugin.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != hostplugin.Subtype.String() {
				badFields[globals.TypeField] = "Doesn't match the parent resource's type."
			}
			if val := req.GetItem().GetSyncIntervalSeconds(); val != nil {
				if val.GetValue() == 0 || val.GetValue() < -1 {
					badFields[globals.SyncIntervalSecondsField] = "Must be -1 or a positive integer."
				}
			}
		}
		return badFields
	})
}

func validateUpdateRequest(ctx context.Context, req *pbs.UpdateHostSetRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if len(req.GetItem().GetPreferredEndpoints()) > 0 {
			_, err := endpoint.NewPreferencer(ctx, endpoint.WithPreferenceOrder(req.GetItem().GetPreferredEndpoints()))
			if err != nil {
				badFields[globals.PreferredEndpointsField] = fmt.Errorf("Error parsing preferred endpoints: %w.", err).Error()
			}
		}
		switch globals.ResourceInfoFromPrefix(req.GetId()).Subtype {
		case static.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != static.Subtype.String() {
				badFields[globals.TypeField] = "Cannot modify the resource type."
			}
		case hostplugin.Subtype:
			if val := req.GetItem().GetSyncIntervalSeconds(); val != nil {
				if val.GetValue() == 0 || val.GetValue() < -1 {
					badFields[globals.SyncIntervalSecondsField] = "Must be -1 or a positive integer."
				}
			}
		}
		return badFields
	}, globals.StaticHostSetPrefix, globals.PluginHostSetPrefix, globals.PluginHostSetPreviousPrefix)
}

func validateDeleteRequest(req *pbs.DeleteHostSetRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, globals.StaticHostSetPrefix, globals.PluginHostSetPrefix, globals.PluginHostSetPreviousPrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetHostCatalogId()), globals.StaticHostCatalogPrefix, globals.PluginHostCatalogPrefix, globals.PluginHostCatalogPreviousPrefix) {
		badFields[globals.HostCatalogIdField] = "The field is incorrectly formatted."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields[globals.FilterField] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddRequest(req *pbs.AddHostSetHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.StaticHostSetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetHostIds()) == 0 {
		badFields[globals.HostIdsField] = "Must be non-empty."
	}
	for _, id := range req.GetHostIds() {
		if !handlers.ValidId(handlers.Id(id), globals.StaticHostPrefix) {
			badFields[globals.HostIdsField] = "Incorrectly formatted host identifier."
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
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.StaticHostSetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	for _, id := range req.GetHostIds() {
		if !handlers.ValidId(handlers.Id(id), globals.StaticHostPrefix) {
			badFields[globals.HostIdsField] = "Incorrectly formatted host identifier."
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
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.StaticHostSetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetHostIds()) == 0 {
		badFields[globals.HostIdsField] = "Must be non-empty."
	}
	for _, id := range req.GetHostIds() {
		if !handlers.ValidId(handlers.Id(id), globals.StaticHostPrefix) {
			badFields[globals.HostIdsField] = "Incorrectly formatted host identifier."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
