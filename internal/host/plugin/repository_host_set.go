package plugin

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/endpoint"
	"github.com/hashicorp/boundary/internal/oplog"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	hcpb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// CreateSet inserts s into the repository and returns a new HostSet
// containing the host set's PublicId. s is not changed. s must contain a
// valid CatalogId. s must not contain a PublicId. The PublicId is
// generated and assigned by this method. opt is ignored.
//
// Both s.Name and s.Description are optional. If s.Name is set, it must be
// unique within s.CatalogId.
func (r *Repository) CreateSet(ctx context.Context, scopeId string, s *HostSet, _ ...Option) (*HostSet, *hostplugin.Plugin, error) {
	const op = "plugin.(Repository).CreateSet"
	if s == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "nil HostSet")
	}
	if s.HostSet == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "nil embedded HostSet")
	}
	if s.CatalogId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	}
	if s.PublicId != "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	if scopeId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	if s.Attributes == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "nil attributes")
	}
	s = s.clone()

	c, err := r.getCatalog(ctx, s.CatalogId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("looking up catalog"))
	}
	per, err := r.getPersistedDataForCatalog(ctx, c)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("looking up persisted data"))
	}
	id, err := newHostSetId(ctx)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	s.PublicId = id

	plgClient, ok := r.plugins[c.GetPluginId()]
	if !ok || plgClient == nil {
		return nil, nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("plugin %q not available", c.GetPluginId()))
	}

	plgHc, err := toPluginCatalog(ctx, c)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	plgHs, err := toPluginSet(ctx, s)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	if _, err := plgClient.OnCreateSet(ctx, &plgpb.OnCreateSetRequest{Catalog: plgHc, Set: plgHs, Persisted: per}); err != nil {
		if status.Code(err) != codes.Unimplemented {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var preferredEndpoints []interface{}
	if s.PreferredEndpoints != nil {
		preferredEndpoints = make([]interface{}, 0, len(s.PreferredEndpoints))
		for i, e := range s.PreferredEndpoints {
			obj, err := host.NewPreferredEndpoint(ctx, s.PublicId, uint32(i+1), e)
			if err != nil {
				return nil, nil, errors.Wrap(ctx, err, op)
			}
			preferredEndpoints = append(preferredEndpoints, obj)
		}
	}

	var returnedHostSet *HostSet
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, len(preferredEndpoints)+2)
			ticket, err := w.GetTicket(s)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			returnedHostSet = s.clone()

			var hsOplogMsg oplog.Message
			if err := w.Create(ctx, returnedHostSet, db.NewOplogMsg(&hsOplogMsg)); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			msgs = append(msgs, &hsOplogMsg)

			if len(preferredEndpoints) > 0 {
				peOplogMsgs := make([]*oplog.Message, 0, len(preferredEndpoints))
				if err := w.CreateItems(ctx, preferredEndpoints, db.NewOplogMsgs(&peOplogMsgs)); err != nil {
					return err
				}
				msgs = append(msgs, peOplogMsgs...)
			}

			metadata := s.oplog(oplog.OpType_OP_TYPE_CREATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in catalog: %s: name %s already exists", s.CatalogId, s.Name)))
		}
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in catalog: %s", s.CatalogId)))
	}
	plg, err := r.getPlugin(ctx, c.GetPluginId())
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return returnedHostSet, plg, nil
}

// LookupSet will look up a host set in the repository and return the host
// set. If the host set is not found, it will return nil, nil.
// All options are ignored.
func (r *Repository) LookupSet(ctx context.Context, publicId string, opt ...host.Option) (*HostSet, *hostplugin.Plugin, error) {
	const op = "plugin.(Repository).LookupSet"
	if publicId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}

	sets, plg, err := r.getSets(ctx, publicId, "", opt...)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	switch {
	case len(sets) == 0:
		return nil, nil, nil // not an error to return no rows for a "lookup"
	case len(sets) > 1:
		return nil, nil, errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("%s matched more than 1 ", publicId))
	default:
		return sets[0], plg, nil
	}
}

// ListSets returns a slice of HostSets for the catalogId. WithLimit is the
// only option supported.
func (r *Repository) ListSets(ctx context.Context, catalogId string, opt ...host.Option) ([]*HostSet, *hostplugin.Plugin, error) {
	const op = "plugin.(Repository).ListSets"
	if catalogId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing catalog id")
	}

	sets, plg, err := r.getSets(ctx, "", catalogId, opt...)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return sets, plg, nil
}

func (r *Repository) getSets(ctx context.Context, publicId string, catalogId string, opt ...host.Option) ([]*HostSet, *hostplugin.Plugin, error) {
	const op = "plugin.(Repository).getSets"
	if publicId == "" && catalogId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing search criteria: both host set id and catalog id are empty")
	}
	if publicId != "" && catalogId != "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "searching for both a host set id and a catalog id is not supported")
	}

	opts, err := host.GetOpts(opt...)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	limit := r.defaultLimit
	if opts.WithLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.WithLimit
	}

	args := make([]interface{}, 0, 1)
	var where string

	switch {
	case publicId != "":
		where, args = "public_id = ?", append(args, publicId)
	default:
		where, args = "catalog_id = ?", append(args, catalogId)
	}

	dbArgs := []db.Option{db.WithLimit(limit)}

	if opts.WithOrderByCreateTime {
		if opts.Ascending {
			dbArgs = append(dbArgs, db.WithOrder("create_time asc"))
		} else {
			dbArgs = append(dbArgs, db.WithOrder("create_time"))
		}
	}

	var aggHostSets []*hostSetAgg
	if err := r.reader.SearchWhere(ctx, &aggHostSets, where, args, dbArgs...); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s", publicId)))
	}

	if len(aggHostSets) == 0 {
		return nil, nil, nil
	}
	plgId := aggHostSets[0].PluginId

	sets := make([]*HostSet, 0, len(aggHostSets))
	for _, agg := range aggHostSets {
		hs, err := agg.toHostSet(ctx)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		sets = append(sets, hs)
	}
	var plg *hostplugin.Plugin
	if plgId != "" {
		plg, err = r.getPlugin(ctx, plgId)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
	}

	return sets, plg, nil
}

// hostSetAgg is a view that aggregates the host set's value objects in to
// string fields delimited with the aggregateDelimiter of "|"
type hostSetAgg struct {
	PublicId           string `gorm:"primary_key"`
	CatalogId          string
	PluginId           string
	Name               string
	Description        string
	CreateTime         *timestamp.Timestamp
	UpdateTime         *timestamp.Timestamp
	Version            uint32
	Attributes         []byte
	PreferredEndpoints string
}

func (agg *hostSetAgg) toHostSet(ctx context.Context) (*HostSet, error) {
	const op = "plugin.(hostSetAgg).toHostSet"
	const aggregateDelimiter = "|"
	const priorityDelimiter = "="
	hs := allocHostSet()
	hs.PublicId = agg.PublicId
	hs.CatalogId = agg.CatalogId
	hs.Name = agg.Name
	hs.Description = agg.Description
	hs.CreateTime = agg.CreateTime
	hs.UpdateTime = agg.UpdateTime
	hs.Version = agg.Version
	hs.Attributes = agg.Attributes
	if agg.PreferredEndpoints != "" {
		eps := strings.Split(agg.PreferredEndpoints, aggregateDelimiter)
		if len(eps) > 0 {
			// We want to protect against someone messing with the DB
			// and not panic, so we do a bit of a dance here
			var sortErr error
			sort.Slice(eps, func(i, j int) bool {
				epi := strings.Split(eps[i], priorityDelimiter)
				if len(epi) != 2 {
					sortErr = errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("preferred endpoint %s had unexpected fields", eps[i]))
					return false
				}
				epj := strings.Split(eps[j], priorityDelimiter)
				if len(epj) != 2 {
					sortErr = errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("preferred endpoint %s had unexpected fields", eps[j]))
					return false
				}
				indexi, err := strconv.Atoi(epi[0])
				if err != nil {
					sortErr = errors.Wrap(ctx, err, op)
					return false
				}
				indexj, err := strconv.Atoi(epj[0])
				if err != nil {
					sortErr = errors.Wrap(ctx, err, op)
					return false
				}
				return indexi < indexj
			})
			if sortErr != nil {
				return nil, sortErr
			}
			for i, ep := range eps {
				// At this point they're in the correct order, but we still
				// have to strip off the priority
				eps[i] = strings.Split(ep, priorityDelimiter)[1]
			}
			hs.PreferredEndpoints = eps
		}
	}
	return hs, nil
}

// TableName returns the table name for gorm
func (agg *hostSetAgg) TableName() string { return "host_plugin_host_set_with_value_obj" }

// toPluginSet returns a host set in the format expected by the host plugin system.
func toPluginSet(ctx context.Context, in *HostSet) (*pb.HostSet, error) {
	const op = "plugin.toPluginCatalog"
	if in == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil storage plugin")
	}
	hs := &pb.HostSet{
		Id: in.GetPublicId(),
	}
	if in.GetAttributes() != nil {
		attrs := &structpb.Struct{}
		if err := proto.Unmarshal(in.GetAttributes(), attrs); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to marshal attributes"))
		}
		hs.Attributes = attrs
	}
	return hs, nil
}

// Endpoints provides all the endpoints available for a given set id.
// An error is returned if the set, related catalog, or related plugin are
// unable to be retrieved.  If a host does not contain an addressible endpoint
// it is not included in the resulting slice of endpoints.
func (r *Repository) Endpoints(ctx context.Context, setIds []string) ([]*host.Endpoint, error) {
	const op = "plugin.(Repository).Endpoints"
	if len(setIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no set ids")
	}
	var setAggs []*hostSetAgg
	if err := r.reader.SearchWhere(ctx, &setAggs, "public_id in (?)", []interface{}{setIds}); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("can't retrieve sets %v", setIds)))
	}
	if len(setAggs) == 0 {
		return nil, nil
	}

	type setInfo struct {
		preferredEndpoint endpoint.Option
		plgSet *pb.HostSet
	}

	type catalogInfo struct{
		publicId string
		plg plgpb.HostPluginServiceServer
		setInfos map[string]*setInfo
		plgCat *hcpb.HostCatalog
		persisted *plgpb.HostCatalogPersisted
	}

	catalogInfos := make(map[string]*catalogInfo)
	for _, ag := range setAggs {
		ci, ok := catalogInfos[ag.CatalogId]
		if !ok {
			ci = &catalogInfo{
				publicId: ag.CatalogId,
				setInfos: make(map[string]*setInfo),
			}
		}
		ci.plg, ok = r.plugins[ag.PluginId]
		if !ok {
			return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("expected plugin %q not available", ag.PluginId))
		}

		s, err := ag.toHostSet(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		si, ok := ci.setInfos[s.GetPublicId()]
		if !ok {
			si = &setInfo{}
		}
		si.preferredEndpoint = endpoint.WithPreferenceOrder(s.GetPreferredEndpoints())
		si.plgSet, err = toPluginSet(ctx, s)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("converting set %q to plugin set", s.GetPublicId())))
		}

		ci.setInfos[s.GetPublicId()] = si
		catalogInfos[ag.CatalogId] = ci
	}

	catIds := make([]string, 0, len(catalogInfos))
	for k := range catalogInfos {
		catIds = append(catIds, k)
	}
	var cats []*HostCatalog
	if err := r.reader.SearchWhere(ctx, &cats, "public_id in (?)", []interface{}{catIds}); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("can't retrieve catalogs %v", catIds)))
	}
	if len(cats) == 0 {
		return nil, errors.New(ctx, errors.NotSpecificIntegrity, op, "no catalogs returned for retrieved sets")
	}
	for _, c := range cats {
		ci, ok := catalogInfos[c.GetPublicId()]
		if !ok {
			return nil, errors.New(ctx, errors.NotSpecificIntegrity, op, "catalog returned when no set requested it")
		}
		plgCat, err := toPluginCatalog(ctx, c)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("storage to plugin catalog conversion"))
		}
		ci.plgCat = plgCat

		// TODO: Do these looksups from the DB in bulk instead of individually.
		per, err := r.getPersistedDataForCatalog(ctx, c)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("persisted catalog lookup failed"))
		}
		ci.persisted = per
		catalogInfos[c.GetPublicId()] = ci
	}

	// For writing the hosts to the db so data warehouse doesn't complain
	var hosts []interface{}
	hostIds := map[string]bool{}
	var es []*host.Endpoint
	for _, ci := range catalogInfos {

		var sets []*pb.HostSet
		for _, si := range ci.setInfos {
			sets = append(sets, si.plgSet)
		}

		resp, err := ci.plg.ListHosts(ctx,  &plgpb.ListHostsRequest{
			Catalog: ci.plgCat,
			Sets:    sets,
			//Persisted: ci.persisted,
		})
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		for _, h := range resp.GetHosts() {
			hostId, err := newHostId(ctx, ci.publicId, h.GetExternalId())
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}

			for _, sId := range h.GetSetIds() {
				var opts []endpoint.Option
				if len(h.GetIpAddresses()) > 0 {
					opts = append(opts, endpoint.WithIpAddrs(h.GetIpAddresses()))
				}
				if len(h.GetDnsNames()) > 0 {
					opts = append(opts, endpoint.WithIpAddrs(h.GetDnsNames()))
				}

				si, ok := ci.setInfos[sId]
				if !ok {
					return nil, errors.New(ctx, errors.NotSpecificIntegrity, op, "host is reporting it's part of a set we didn't query for")
				}
				pref, err := endpoint.NewPreferencer(ctx, si.preferredEndpoint)
				if err != nil {
					return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("getting preferencer for set %q", sId)))
				}
				addr, err := pref.Choose(ctx, opts...)
				if err != nil {
					return nil, errors.Wrap(ctx, err, op)
				}
				if addr == "" {
					continue
				}
				es = append(es, &host.Endpoint{
					HostId:  hostId,
					SetId:   sId,
					Address: addr,
				})

				if _, ok := hostIds[hostId]; !ok {
					hostIds[hostId] = true
					host := newHost(ctx, ci.publicId, addr)
					host.PublicId = hostId
					hosts = append(hosts, host)
				}
			}
		}
	}

	if len(hosts) > 0 {
		_, err := r.writer.DoTx(
			ctx,
			db.StdRetryCnt,
			db.ExpBackoff{},
			func(_ db.Reader, w db.Writer) error {
				if _, err := r.writer.DeleteItems(ctx, hosts); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("couldn't delete existing hosts"))
				}
				if err := r.writer.CreateItems(ctx, hosts); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("can't persist hosts"))
				}
				return nil
			})
		if err != nil {
			return nil, err
		}
	}
	return es, nil
}
