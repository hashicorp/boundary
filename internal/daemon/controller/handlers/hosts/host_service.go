package hosts

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/perms"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hosts"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	idActionsTypeMap = map[subtypes.Subtype]action.ActionSet{
		static.Subtype: {
			action.NoOp,
			action.Read,
			action.Update,
			action.Delete,
		},
		plugin.Subtype: {
			action.NoOp,
			action.Read,
		},
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.ActionSet{
		action.Create,
		action.List,
	}
)

const domain = "host"

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.Host{}}, handlers.MaskSource{&pb.Host{}, &pb.StaticHostAttributes{}}); err != nil {
		panic(err)
	}
}

type Service struct {
	pbs.UnsafeHostServiceServer

	staticRepoFn common.StaticRepoFactory
	pluginRepoFn common.PluginHostRepoFactory
}

var _ pbs.HostServiceServer = (*Service)(nil)

// NewService returns a host Service which handles host related requests to boundary and uses the provided
// repositories for storage and retrieval.
func NewService(repoFn common.StaticRepoFactory, pluginRepoFn common.PluginHostRepoFactory) (Service, error) {
	const op = "hosts.NewService"
	if repoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing static repository")
	}
	if pluginRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing plugin host repository")
	}
	return Service{staticRepoFn: repoFn, pluginRepoFn: pluginRepoFn}, nil
}

func (s Service) ListHosts(ctx context.Context, req *pbs.ListHostsRequest) (*pbs.ListHostsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetHostCatalogId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hl, plg, err := s.listFromRepo(ctx, req.GetHostCatalogId())
	if err != nil {
		return nil, err
	}
	if len(hl) == 0 {
		return &pbs.ListHostsResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.Host, 0, len(hl))

	res := perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.Host,
		Pin:     req.GetHostCatalogId(),
	}
	for _, item := range hl {
		res.Id = item.GetPublicId()
		idActions := idActionsTypeMap[subtypes.SubtypeFromId(domain, res.Id)]
		authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), idActions, auth.WithResource(&res)).Strings()
		if len(authorizedActions) == 0 {
			continue
		}

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserData.User.Id)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if plg != nil {
			outputOpts = append(outputOpts, handlers.WithPlugin(plg))
		}
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
		}
		outputOpts = append(outputOpts, handlers.WithHostSetIds(item.GetSetIds()))
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
	return &pbs.ListHostsResponse{Items: finalItems}, nil
}

// GetHost implements the interface pbs.HostServiceServer.
func (s Service) GetHost(ctx context.Context, req *pbs.GetHostRequest) (*pbs.GetHostResponse, error) {
	const op = "hosts.(Service).GetHost"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Read)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if plg != nil {
		outputOpts = append(outputOpts, handlers.WithPlugin(plg))
	}
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		idActions := idActionsTypeMap[subtypes.SubtypeFromId(domain, req.GetId())]
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
	_, authResults := s.parentAndAuthResult(ctx, req.GetItem().GetHostCatalogId(), action.Create)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		idActions := idActionsTypeMap[subtypes.SubtypeFromId(domain, req.GetItem().GetHostCatalogId())]
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
	cat, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Update)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		idActions := idActionsTypeMap[subtypes.SubtypeFromId(domain, req.GetId())]
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

func (s Service) getFromRepo(ctx context.Context, id string) (host.Host, *plugins.PluginInfo, error) {
	var h host.Host
	var plg *plugins.PluginInfo
	switch subtypes.SubtypeFromId(domain, id) {
	case static.Subtype:
		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, nil, err
		}
		h, err = repo.LookupHost(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if h == nil {
			return nil, nil, handlers.NotFoundErrorf("Host %q doesn't exist.", id)
		}
	case plugin.Subtype:
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
	h, err := static.NewHost(catalogId, opts...)
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
	h, err := static.NewHost(catalogId, opts...)
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

func (s Service) listFromRepo(ctx context.Context, catalogId string) ([]host.Host, *plugins.PluginInfo, error) {
	var hosts []host.Host
	var plg *plugins.PluginInfo
	switch subtypes.SubtypeFromId(domain, catalogId) {
	case static.Subtype:
		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, nil, err
		}
		hl, err := repo.ListHosts(ctx, catalogId)
		if err != nil {
			return nil, nil, err
		}
		for _, h := range hl {
			hosts = append(hosts, h)
		}
	case plugin.Subtype:
		repo, err := s.pluginRepoFn()
		if err != nil {
			return nil, nil, err
		}
		hl, hlPlg, err := repo.ListHostsByCatalogId(ctx, catalogId)
		if err != nil {
			return nil, nil, err
		}
		for _, h := range hl {
			hosts = append(hosts, h)
		}
		plg = toPluginInfo(hlPlg)
	}
	return hosts, plg, nil
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
	opts := []auth.Option{auth.WithType(resource.Host), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
	default:
		switch subtypes.SubtypeFromId(domain, id) {
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
		case plugin.Subtype:
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
	switch subtypes.SubtypeFromId(domain, id) {
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
	case plugin.Subtype:
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
	return cat, auth.Verify(ctx, opts...)
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
		case *plugin.Host:
			out.Type = plugin.Subtype.String()
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
	case *plugin.Host:
		if outputFields.Has(globals.IpAddressesField) {
			out.IpAddresses = h.IpAddresses
		}
		if outputFields.Has(globals.DnsNamesField) {
			out.DnsNames = h.DnsNames
		}
		if outputFields.Has(globals.ExternalIdField) {
			out.ExternalId = h.ExternalId
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
		ct := subtypes.SubtypeFromId(domain, req.GetId())
		if ct == subtypes.UnknownSubtype {
			badFields["id"] = "Improperly formatted identifier used."
		}
		return badFields
	}, req, static.HostPrefix, plugin.HostPrefix, plugin.PreviousHostPrefix)
}

func validateCreateRequest(req *pbs.CreateHostRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetHostCatalogId()), static.HostCatalogPrefix) {
			badFields["host_catalog_id"] = "The field is incorrectly formatted."
		}
		switch subtypes.SubtypeFromId(domain, req.GetItem().GetHostCatalogId()) {
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
				badFields["attributes"] = "This is a required field."
			default:
				if attrs.GetAddress() == nil ||
					len(attrs.GetAddress().GetValue()) < static.MinHostAddressLength ||
					len(attrs.GetAddress().GetValue()) > static.MaxHostAddressLength {
					badFields["attributes.address"] = fmt.Sprintf("Address length must be between %d and %d characters.", static.MinHostAddressLength, static.MaxHostAddressLength)
				}
				_, _, err := net.SplitHostPort(attrs.GetAddress().GetValue())
				switch {
				case err == nil:
					badFields["attributes.address"] = "Address for static hosts does not support a port."
				case strings.Contains(err.Error(), "missing port in address"):
					// Bare hostname, which we want
				default:
					badFields["attributes.address"] = fmt.Sprintf("Error parsing address: %v.", err)
				}
			}
		case plugin.Subtype:
			badFields[globals.HostCatalogIdField] = "Cannot manually create hosts for this type of catalog."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateHostRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch subtypes.SubtypeFromId(domain, req.GetId()) {
		case static.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != static.Subtype.String() {
				badFields[globals.TypeField] = "Cannot modify the resource type."
				attrs := req.GetItem().GetStaticHostAttributes()

				if handlers.MaskContains(req.GetUpdateMask().GetPaths(), "attributes.address") {
					switch {
					case attrs == nil:
						badFields["attributes"] = "Attributes field not supplied request"
					default:
						if attrs.GetAddress() == nil ||
							len(strings.TrimSpace(attrs.GetAddress().GetValue())) < static.MinHostAddressLength ||
							len(strings.TrimSpace(attrs.GetAddress().GetValue())) > static.MaxHostAddressLength {
							badFields["attributes.address"] = fmt.Sprintf("Address length must be between %d and %d characters.", static.MinHostAddressLength, static.MaxHostAddressLength)
						}
					}
				}
			}
		case plugin.Subtype:
			badFields[globals.IdField] = "Cannot modify this type of host."
		default:
			badFields["id"] = "Improperly formatted identifier used."
		}
		return badFields
	}, static.HostPrefix)
}

func validateDeleteRequest(req *pbs.DeleteHostRequest) error {
	return handlers.ValidateDeleteRequest(func() map[string]string {
		badFields := map[string]string{}
		switch subtypes.SubtypeFromId(domain, req.GetId()) {
		case plugin.Subtype:
			badFields[globals.IdField] = "Cannot manually delete this type of host."
		}
		return badFields
	}, req, static.HostPrefix)
}

func validateListRequest(req *pbs.ListHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetHostCatalogId()), static.HostCatalogPrefix, plugin.HostCatalogPrefix, plugin.PreviousHostCatalogPrefix) {
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
