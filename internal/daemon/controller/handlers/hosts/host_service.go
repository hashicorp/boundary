// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hosts

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	plugin "github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	"github.com/hashicorp/boundary/internal/util"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hosts"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	idActionsTypeMap = map[globals.Subtype]action.ActionSet{
		static.Subtype: action.NewActionSet(
			action.NoOp,
			action.Read,
			action.Update,
			action.Delete,
		),
		hostplugin.Subtype: action.NewActionSet(
			action.NoOp,
			action.Read,
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
	if maskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.Host{}},
		handlers.MaskSource{&pb.Host{}, &pb.StaticHostAttributes{}},
	); err != nil {
		panic(err)
	}

	// TODO: refactor to remove idActionsMap and CollectionActions package variables
	action.RegisterResource(resource.Host, action.Union(maps.Values(idActionsTypeMap)...), CollectionActions)
}

type Service struct {
	pbs.UnsafeHostServiceServer

	staticRepoFn common.StaticRepoFactory
	pluginRepoFn common.PluginHostRepoFactory
	maxPageSize  uint
}

var _ pbs.HostServiceServer = (*Service)(nil)

// NewService returns a host Service which handles host related requests to boundary and uses the provided
// repositories for storage and retrieval.
func NewService(ctx context.Context, repoFn common.StaticRepoFactory, pluginRepoFn common.PluginHostRepoFactory, maxPageSize uint) (Service, error) {
	const op = "hosts.NewService"
	if repoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing static repository")
	}
	if pluginRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing plugin host repository")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return Service{staticRepoFn: repoFn, pluginRepoFn: pluginRepoFn, maxPageSize: maxPageSize}, nil
}

func (s Service) ListHosts(ctx context.Context, req *pbs.ListHostsRequest) (*pbs.ListHostsResponse, error) {
	const op = "hosts.(Service).ListHosts"
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

	var filterItemFn func(ctx context.Context, item host.Host, plg *plugin.Plugin) (bool, error)
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
		filterItemFn = func(ctx context.Context, item host.Host, plg *plugin.Plugin) (bool, error) {
			outputOpts, ok := newOutputOpts(ctx, item, plg, authResults)
			if !ok {
				return false, nil
			}
			pbItem, err := toProto(ctx, item, outputOpts...)
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
		filterItemFn = func(ctx context.Context, item host.Host, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
	}

	grantsHash, err := authResults.GrantsHash(ctx)
	if err != nil {
		return nil, err
	}

	var listResp *pagination.ListResponse[host.Host]
	var sortBy string
	var plg *plugin.Plugin
	switch globals.ResourceInfoFromPrefix(req.GetHostCatalogId()).Subtype {
	case static.Subtype:
		// Wrap the filter item func that takes a plugin, since the static host
		// domain does not use a plugin.
		staticFilterItemFn := func(ctx context.Context, item host.Host) (bool, error) {
			return filterItemFn(ctx, item, nil)
		}
		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if req.GetListToken() == "" {
			sortBy = "created_time"
			listResp, err = static.ListHosts(ctx, grantsHash, pageSize, staticFilterItemFn, repo, req.GetHostCatalogId())
			if err != nil {
				return nil, err
			}
		} else {
			listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.Host, grantsHash)
			if err != nil {
				return nil, err
			}
			switch st := listToken.Subtype.(type) {
			case *listtoken.PaginationToken:
				sortBy = "created_time"
				listResp, err = static.ListHostsPage(ctx, grantsHash, pageSize, staticFilterItemFn, listToken, repo, req.GetHostCatalogId())
				if err != nil {
					return nil, err
				}
			case *listtoken.StartRefreshToken:
				sortBy = "updated_time"
				listResp, err = static.ListHostsRefresh(ctx, grantsHash, pageSize, staticFilterItemFn, listToken, repo, req.GetHostCatalogId())
				if err != nil {
					return nil, err
				}
			case *listtoken.RefreshToken:
				sortBy = "updated_time"
				listResp, err = static.ListHostsRefreshPage(ctx, grantsHash, pageSize, staticFilterItemFn, listToken, repo, req.GetHostCatalogId())
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
			listResp, plg, err = hostplugin.ListHosts(ctx, grantsHash, pageSize, filterItemFn, repo, req.GetHostCatalogId())
			if err != nil {
				return nil, err
			}
		} else {
			listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.Host, grantsHash)
			if err != nil {
				return nil, err
			}
			switch st := listToken.Subtype.(type) {
			case *listtoken.PaginationToken:
				sortBy = "created_time"
				listResp, plg, err = hostplugin.ListHostsPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, req.GetHostCatalogId())
				if err != nil {
					return nil, err
				}
			case *listtoken.StartRefreshToken:
				sortBy = "updated_time"
				listResp, plg, err = hostplugin.ListHostsRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, req.GetHostCatalogId())
				if err != nil {
					return nil, err
				}
			case *listtoken.RefreshToken:
				sortBy = "updated_time"
				listResp, plg, err = hostplugin.ListHostsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, req.GetHostCatalogId())
				if err != nil {
					return nil, err
				}
			default:
				return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
			}
		}
	}

	finalItems := make([]*pb.Host, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		outputOpts, ok := newOutputOpts(ctx, item, plg, authResults)
		if !ok {
			continue
		}
		pbItem, err := toProto(ctx, item, outputOpts...)
		if err != nil {
			continue
		}
		finalItems = append(finalItems, pbItem)
	}
	respType := "delta"
	if listResp.CompleteListing {
		respType = "complete"
	}
	resp := &pbs.ListHostsResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}

	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_HOST)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// GetHost implements the interface pbs.HostServiceServer.
func (s Service) GetHost(ctx context.Context, req *pbs.GetHostRequest) (*pbs.GetHostResponse, error) {
	const op = "hosts.(Service).GetHost"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Read, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	h, plg, err := s.getFromRepo(ctx, req.GetId())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, h.GetPublicId(), idActions).Strings()))
	}
	outputOpts = append(outputOpts, handlers.WithHostSetIds(h.GetSetIds()))
	item, err := toProto(ctx, h, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetHostResponse{Item: item}, nil
}

// CreateHost implements the interface pbs.HostServiceServer.
func (s Service) CreateHost(ctx context.Context, req *pbs.CreateHostRequest) (*pbs.CreateHostResponse, error) {
	const op = "hosts.(Service).CreateHost"

	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetItem().GetHostCatalogId(), action.Create, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	h, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem().GetHostCatalogId(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, h.GetPublicId(), idActions).Strings()))
	}

	item, err := toProto(ctx, h, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateHostResponse{
		Item: item,
		Uri:  fmt.Sprintf("hosts/%s", item.GetId()),
	}, nil
}

// UpdateHost implements the interface pbs.HostServiceServer.
func (s Service) UpdateHost(ctx context.Context, req *pbs.UpdateHostRequest) (*pbs.UpdateHostResponse, error) {
	const op = "hosts.(Service).UpdateHost"

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	cat, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Update, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	h, err := s.updateInRepo(ctx, authResults.Scope.GetId(), cat.GetPublicId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, h.GetPublicId(), idActions).Strings()))
	}
	outputOpts = append(outputOpts, handlers.WithHostSetIds(h.GetSetIds()))

	item, err := toProto(ctx, h, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateHostResponse{Item: item}, nil
}

// DeleteHost implements the interface pbs.HostServiceServer.
func (s Service) DeleteHost(ctx context.Context, req *pbs.DeleteHostRequest) (*pbs.DeleteHostResponse, error) {
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

func (s Service) getFromRepo(ctx context.Context, id string) (host.Host, *plugins.PluginInfo, error) {
	var h host.Host
	var plg *plugins.PluginInfo
	switch globals.ResourceInfoFromPrefix(id).Subtype {
	case static.Subtype:
		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, nil, err
		}
		h, err = repo.LookupHost(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if util.IsNil(h) {
			return nil, nil, handlers.NotFoundErrorf("Host %q doesn't exist.", id)
		}
	case hostplugin.Subtype:
		repo, err := s.pluginRepoFn()
		if err != nil {
			return nil, nil, err
		}
		ph, hPlg, err := repo.LookupHost(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if ph == nil {
			return nil, nil, handlers.NotFoundErrorf("Host %q doesn't exist.", id)
		}
		h = ph
		plg = toPluginInfo(hPlg)
	}
	return h, plg, nil
}

func (s Service) createInRepo(ctx context.Context, projectId, catalogId string, item *pb.Host) (*static.Host, error) {
	const op = "hosts.(Service).createInRepo"
	ha := item.GetStaticHostAttributes()
	var opts []static.Option
	if ha.GetAddress() != nil {
		opts = append(opts, static.WithAddress(ha.GetAddress().GetValue()))
	}
	if item.GetName() != nil {
		opts = append(opts, static.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, static.WithDescription(item.GetDescription().GetValue()))
	}
	h, err := static.NewHost(ctx, catalogId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to build host for creation"))
	}

	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, err := repo.CreateHost(ctx, projectId, h)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to create host"))
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create host but no error returned from repository.")
	}
	return out, nil
}

func (s Service) updateInRepo(ctx context.Context, projectId, catalogId, id string, mask []string, item *pb.Host) (*static.Host, error) {
	const op = "hosts.(Service).updateInRepo"
	ha := item.GetStaticHostAttributes()
	var opts []static.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, static.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, static.WithName(name.GetValue()))
	}
	if addr := ha.GetAddress(); addr != nil {
		opts = append(opts, static.WithAddress(addr.GetValue()))
	}
	h, err := static.NewHost(ctx, catalogId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Unable to build host for update"))
	}
	h.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateHost(ctx, projectId, h, item.GetVersion(), dbMask)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update host"))
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Host %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) deleteFromRepo(ctx context.Context, projectId, id string) (bool, error) {
	const op = "hosts.(Service).deleteFromRepo"
	repo, err := s.staticRepoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteHost(ctx, projectId, id)
	if err != nil {
		return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete host"))
	}
	return rows > 0, nil
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
		switch globals.ResourceInfoFromPrefix(id).Subtype {
		case static.Subtype:
			h, err := staticRepo.LookupHost(ctx, id)
			if err != nil {
				res.Error = err
				return nil, res
			}
			if h == nil {
				res.Error = handlers.NotFoundError()
				return nil, res
			}
			parentId = h.GetCatalogId()
		case hostplugin.Subtype:
			h, _, err := pluginRepo.LookupHost(ctx, id)
			if err != nil {
				res.Error = err
				return nil, res
			}
			if h == nil {
				res.Error = handlers.NotFoundError()
				return nil, res
			}
			parentId = h.GetCatalogId()
		}
		opts = append(opts, auth.WithId(id))
	}

	var cat host.Catalog
	switch globals.ResourceInfoFromPrefix(id).Subtype {
	case static.Subtype:
		stcat, err := staticRepo.LookupCatalog(ctx, parentId)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if stcat == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		cat = stcat
	case hostplugin.Subtype:
		plcat, _, err := pluginRepo.LookupCatalog(ctx, parentId)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if plcat == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		cat = plcat
	}
	opts = append(opts, auth.WithScopeId(cat.GetProjectId()), auth.WithPin(parentId))
	return cat, auth.Verify(ctx, resource.Host, opts...)
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

func newOutputOpts(ctx context.Context, item host.Host, plg *plugin.Plugin, authResults auth.VerifyResults) ([]handlers.Option, bool) {
	res := perms.Resource{
		ScopeId:       authResults.Scope.Id,
		ParentScopeId: authResults.Scope.ParentScopeId,
		Type:          resource.Host,
		Pin:           item.GetCatalogId(),
		Id:            item.GetPublicId(),
	}
	res.Id = item.GetPublicId()
	idActions := idActionsTypeMap[globals.ResourceInfoFromPrefix(res.Id).Subtype]
	authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), idActions, auth.WithResource(&res)).Strings()
	if len(authorizedActions) == 0 {
		return nil, false
	}

	outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if plg != nil {
		outputOpts = append(outputOpts, handlers.WithPlugin(toPluginInfo(plg)))
	}
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
	}
	outputOpts = append(outputOpts, handlers.WithHostSetIds(item.GetSetIds()))
	return outputOpts, true
}

func toProto(ctx context.Context, in host.Host, opt ...handlers.Option) (*pb.Host, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building host proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.Host{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.HostCatalogIdField) {
		out.HostCatalogId = in.GetCatalogId()
	}
	if outputFields.Has(globals.TypeField) {
		switch in.(type) {
		case *static.Host:
			out.Type = static.Subtype.String()
		case *hostplugin.Host:
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
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
	}
	if outputFields.Has(globals.HostSetIdsField) && len(opts.WithHostSetIds) > 0 {
		out.HostSetIds = opts.WithHostSetIds
	}
	if outputFields.Has(globals.AttributesField) {
		switch h := in.(type) {
		case *static.Host:
			out.Attrs = &pb.Host_StaticHostAttributes{
				StaticHostAttributes: &pb.StaticHostAttributes{
					Address: wrapperspb.String(h.GetAddress()),
				},
			}
		}
	}
	if outputFields.Has(globals.PluginField) {
		out.Plugin = opts.WithPlugin
	}
	switch h := in.(type) {
	case *hostplugin.Host:
		if outputFields.Has(globals.IpAddressesField) {
			out.IpAddresses = h.IpAddresses
		}
		if outputFields.Has(globals.DnsNamesField) {
			out.DnsNames = h.DnsNames
		}
		if outputFields.Has(globals.ExternalIdField) {
			out.ExternalId = h.ExternalId
		}
		if outputFields.Has(globals.ExternalNameField) {
			out.ExternalName = h.ExternalName
		}
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
//   - The type asserted by the ID and/or field is known
//   - If relevant, the type derived from the id prefix matches what is claimed by the type field
func validateGetRequest(req *pbs.GetHostRequest) error {
	return handlers.ValidateGetRequest(func() map[string]string {
		badFields := map[string]string{}
		ct := globals.ResourceInfoFromPrefix(req.GetId()).Subtype
		if ct == globals.UnknownSubtype {
			badFields["id"] = "Improperly formatted identifier used."
		}
		return badFields
	}, req, globals.StaticHostPrefix, globals.PluginHostPrefix, globals.PluginHostPreviousPrefix)
}

func validateCreateRequest(req *pbs.CreateHostRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetHostCatalogId()), globals.StaticHostCatalogPrefix) {
			badFields["host_catalog_id"] = "The field is incorrectly formatted."
		}
		switch globals.ResourceInfoFromPrefix(req.GetItem().GetHostCatalogId()).Subtype {
		case static.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != static.Subtype.String() {
				badFields[globals.TypeField] = "Doesn't match the parent resource's type."
			}
			if len(req.GetItem().GetIpAddresses()) > 0 {
				badFields[globals.IpAddressesField] = "This field is not supported for this host type."
			}
			if len(req.GetItem().GetDnsNames()) > 0 {
				badFields[globals.DnsNamesField] = "This field is not supported for this host type."
			}
			attrs := req.GetItem().GetStaticHostAttributes()
			switch {
			case attrs == nil:
				badFields[globals.AttributesField] = "This is a required field."
			default:
				if attrs.GetAddress() == nil ||
					len(attrs.GetAddress().GetValue()) < static.MinHostAddressLength ||
					len(attrs.GetAddress().GetValue()) > static.MaxHostAddressLength {
					badFields[globals.AttributesAddressField] = fmt.Sprintf("Address length must be between %d and %d characters.", static.MinHostAddressLength, static.MaxHostAddressLength)
				} else {
					_, port, err := util.SplitHostPort(attrs.GetAddress().GetValue())
					if err != nil && !errors.Is(err, util.ErrMissingPort) {
						badFields[globals.AttributesAddressField] = fmt.Sprintf("Error parsing address: %v.", err)
					}
					if port != "" {
						badFields[globals.AttributesAddressField] = "Address for static hosts does not support a port."
					}
				}
			}
		case hostplugin.Subtype:
			badFields[globals.HostCatalogIdField] = "Cannot manually create hosts for this type of catalog."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateHostRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch globals.ResourceInfoFromPrefix(req.GetId()).Subtype {
		case static.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != static.Subtype.String() {
				badFields[globals.TypeField] = "Cannot modify the resource type."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), globals.AttributesAddressField) {
				attrs := req.GetItem().GetStaticHostAttributes()
				switch {
				case attrs == nil:
					badFields[globals.AttributesField] = "Attributes field not supplied in request"
				default:
					if attrs.GetAddress() == nil ||
						len(strings.TrimSpace(attrs.GetAddress().GetValue())) < static.MinHostAddressLength ||
						len(strings.TrimSpace(attrs.GetAddress().GetValue())) > static.MaxHostAddressLength {
						badFields[globals.AttributesAddressField] = fmt.Sprintf("Address length must be between %d and %d characters.", static.MinHostAddressLength, static.MaxHostAddressLength)
					} else {
						_, port, err := util.SplitHostPort(attrs.GetAddress().GetValue())
						if err != nil && !errors.Is(err, util.ErrMissingPort) {
							badFields[globals.AttributesAddressField] = fmt.Sprintf("Error parsing address: %v.", err)
						}
						if port != "" {
							badFields[globals.AttributesAddressField] = "Address for static hosts does not support a port."
						}
					}
				}
			}
		case hostplugin.Subtype:
			badFields[globals.IdField] = "Cannot modify this type of host."
		default:
			badFields["id"] = "Improperly formatted identifier used."
		}
		return badFields
	}, globals.StaticHostPrefix)
}

func validateDeleteRequest(req *pbs.DeleteHostRequest) error {
	return handlers.ValidateDeleteRequest(func() map[string]string {
		badFields := map[string]string{}
		switch globals.ResourceInfoFromPrefix(req.GetId()).Subtype {
		case hostplugin.Subtype:
			badFields[globals.IdField] = "Cannot manually delete this type of host."
		}
		return badFields
	}, req, globals.StaticHostPrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetHostCatalogId()), globals.StaticHostCatalogPrefix, globals.PluginHostCatalogPrefix, globals.PluginHostCatalogPreviousPrefix) {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}
