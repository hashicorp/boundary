package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/endpoint"
	"github.com/hashicorp/boundary/internal/oplog"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
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

	c, per, err := r.getCatalog(ctx, s.CatalogId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("looking up catalog"))
	}
	id, err := newHostSetId(ctx)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	s.PublicId = id
	s.LastSyncTime = timestamp.New(time.Unix(0, 0))
	s.NeedSync = true

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

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
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

	// The set now exists in the plugin, sync it immediately.
	_ = r.scheduler.UpdateJobNextRunInAtLeast(ctx, setSyncJobName, 0)

	plg, err := r.getPlugin(ctx, c.GetPluginId())
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return returnedHostSet, plg, nil
}

// LookupSet will look up a host set in the repository and return the host set,
// as well as host IDs that match. If the host set is not found, it will return
// nil, nil, nil. No options are currently supported.
func (r *Repository) LookupSet(ctx context.Context, publicId string, _ ...host.Option) (*HostSet, *hostplugin.Plugin, error) {
	const op = "plugin.(Repository).LookupSet"
	if publicId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}

	sets, plg, err := r.getSets(ctx, publicId, "")
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	switch {
	case len(sets) == 0:
		return nil, nil, nil // not an error to return no rows for a "lookup"
	case len(sets) > 1:
		return nil, nil, errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("%s matched more than 1 ", publicId))
	}

	return sets[0], plg, nil
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

// DeleteSet deletes the host set for the provided id from the repository
// returning a count of the number of records deleted. All options are
// ignored.
func (r *Repository) DeleteSet(ctx context.Context, scopeId string, publicId string, _ ...Option) (int, error) {
	const op = "plugin.(Repository).DeleteSet"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	if scopeId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}

	sets, plg, err := r.getSets(ctx, publicId, "")
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	if len(sets) != 1 {
		return db.NoRowsAffected, nil
	}
	s := sets[0]

	c, p, err := r.getCatalog(ctx, s.GetCatalogId())
	if err != nil && errors.IsNotFoundError(err) {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	if c == nil {
		return db.NoRowsAffected, nil
	}

	plgClient, ok := r.plugins[plg.GetPublicId()]
	if !ok || plgClient == nil {
		return 0, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("plugin %q not available", c.GetPluginId()))
	}
	plgHc, err := toPluginCatalog(ctx, c)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	plgHs, err := toPluginSet(ctx, s)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	_, err = plgClient.OnDeleteSet(ctx, &plgpb.OnDeleteSetRequest{Catalog: plgHc, Persisted: p, Set: plgHs})
	if err != nil {
		// Even if the plugin returns an error, we ignore it and proceed
		// with deleting the set.
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			ds := s.clone()
			rowsDeleted, err = w.Delete(ctx, ds, db.WithOplog(oplogWrapper, s.oplog(oplog.OpType_OP_TYPE_DELETE)))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)

	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("delete failed for %s", s.PublicId)))
	}

	return rowsDeleted, nil
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

// toPluginSet returns a host set in the format expected by the host plugin system.
func toPluginSet(ctx context.Context, in *HostSet) (*pb.HostSet, error) {
	const op = "plugin.toPluginSet"
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

	// Fist, look up the sets corresponding to the set IDs
	var setAggs []*hostSetAgg
	if err := r.reader.SearchWhere(ctx, &setAggs, "public_id in (?)", []interface{}{setIds}); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("can't retrieve sets %v", setIds)))
	}
	if len(setAggs) == 0 {
		return nil, nil
	}
	setIdToSet := make(map[string]*HostSet, len(setAggs))
	for _, s := range setAggs {
		var err error
		setIdToSet[s.PublicId], err = s.toHostSet(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	var setMembers []*HostSetMember
	if err := r.reader.SearchWhere(ctx, &setMembers, "set_id in (?)", []interface{}{setIds}); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("can't retrieve set members for sets %v", setIds)))
	}
	if len(setMembers) == 0 {
		return nil, nil
	}

	hostIdToSetIds := make(map[string][]string)
	for _, m := range setMembers {
		hostIdToSetIds[m.GetHostId()] = append(hostIdToSetIds[m.GetHostId()], m.GetSetId())
	}
	var hostIds []string
	for hid := range hostIdToSetIds {
		hostIds = append(hostIds, hid)
	}
	var hostAggs []*hostAgg
	if err := r.reader.SearchWhere(ctx, &hostAggs, "public_id in (?)", []interface{}{hostIds}); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("can't retrieve hosts %v", hostIds)))
	}
	if len(hostAggs) == 0 {
		return nil, nil
	}

	var es []*host.Endpoint
	for _, ha := range hostAggs {
		h := ha.toHost()
		for _, sId := range hostIdToSetIds[h.GetPublicId()] {
			s := setIdToSet[sId]
			pref, err := endpoint.NewPreferencer(ctx, endpoint.WithPreferenceOrder(s.GetPreferredEndpoints()))
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("getting preferencer for set %q", sId)))
			}
			var opts []endpoint.Option
			if len(h.GetIpAddresses()) > 0 {
				opts = append(opts, endpoint.WithIpAddrs(h.GetIpAddresses()))
			}
			if len(h.GetDnsNames()) > 0 {
				opts = append(opts, endpoint.WithIpAddrs(h.GetDnsNames()))
			}
			addr, err := pref.Choose(ctx, opts...)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			if addr == "" {
				continue
			}
			es = append(es, &host.Endpoint{
				HostId:  h.GetPublicId(),
				SetId:   sId,
				Address: addr,
			})
		}
	}

	return es, nil
}
