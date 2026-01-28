// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/endpoint"
	"github.com/hashicorp/boundary/internal/libs/patchstruct"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/util"
	hcpb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// normalizeCatalogAttributes allows a plugin to normalize set attributes before
// they are saved
func normalizeSetAttributes(ctx context.Context, plgClient plgpb.HostPluginServiceClient, plgHc *hcpb.HostCatalog, plgHs *pb.HostSet) error {
	const op = "plugin.(Repository).normalizeSetAttributes"
	switch {
	case util.IsNil(plgClient):
		return errors.New(ctx, errors.InvalidParameter, op, "plugin client is nil")
	case plgHs == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "host set is nil")
	case plgHc.GetWorkerFilter().GetValue() != "" && plgHc.GetPlugin() == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "plugin data is not available on host catalog with worker filter")
	case plgHs.GetAttributes() == nil:
		return nil
	}

	ret, err := plgClient.NormalizeSetData(ctx, &plgpb.NormalizeSetDataRequest{
		Attributes: plgHs.GetAttributes(),
		Plugin:     plgHc.GetPlugin(),
	})
	switch {
	case err == nil:
		if ret.Attributes != nil {
			plgHs.Attrs = &pb.HostSet_Attributes{
				Attributes: ret.Attributes,
			}
		}
	case status.Code(err) == codes.Unimplemented:
		// Do nothing
	default:
		return errors.Wrap(ctx, err, op, errors.WithMsg("error asking plugin to normalize set data"))
	}

	return nil
}

// CreateSet inserts s into the repository and returns a new HostSet
// containing the host set's PublicId. s is not changed. s must contain a
// valid CatalogId. s must not contain a PublicId. The PublicId is
// generated and assigned by this method. opt is ignored.
//
// Both s.Name and s.Description are optional. If s.Name is set, it must be
// unique within s.CatalogId.
func (r *Repository) CreateSet(ctx context.Context, projectId string, s *HostSet, _ ...Option) (*HostSet, *plugin.Plugin, error) {
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
	if projectId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}
	if s.SyncIntervalSeconds < -1 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "invalid sync interval")
	}
	if s.Attributes == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "nil attributes")
	}
	s = s.clone()

	// Use PatchBytes' functionality that does not add keys where the values
	// are nil to the resulting struct since we do not want to store nil valued
	// attributes.
	var err error
	s.Attributes, err = patchstruct.PatchBytes([]byte{}, s.Attributes)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

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

	plg, err := r.getPlugin(ctx, c.GetPluginId())
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	plgHc, err := toPluginCatalog(ctx, c, plg)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	plgHs, err := toPluginSet(ctx, s)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	plgClient, err := pluginClientFactoryFn(ctx, plgHc, r.plugins)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	if plgHs.GetAttributes() != nil {
		if err := normalizeSetAttributes(ctx, plgClient, plgHc, plgHs); err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		if s.Attributes, err = proto.Marshal(plgHs.GetAttributes()); err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
	}

	var preferredEndpoints []*host.PreferredEndpoint
	if s.PreferredEndpoints != nil {
		preferredEndpoints = make([]*host.PreferredEndpoint, 0, len(s.PreferredEndpoints))
		for i, e := range s.PreferredEndpoints {
			obj, err := host.NewPreferredEndpoint(ctx, s.PublicId, uint32(i+1), e)
			if err != nil {
				return nil, nil, errors.Wrap(ctx, err, op)
			}
			preferredEndpoints = append(preferredEndpoints, obj)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var calledPluginSuccessfully bool

	var returnedHostSet *HostSet
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, len(preferredEndpoints)+2)
			ticket, err := w.GetTicket(ctx, s)
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

			if !calledPluginSuccessfully {
				if _, err := plgClient.OnCreateSet(ctx, &plgpb.OnCreateSetRequest{Catalog: plgHc, Set: plgHs, Persisted: per}); err != nil {
					if status.Code(err) != codes.Unimplemented {
						return errors.Wrap(ctx, err, op)
					}
				}
				calledPluginSuccessfully = true
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
	_ = r.scheduler.UpdateJobNextRunInAtLeast(ctx, setSyncJobName, 0, scheduler.WithRunNow(true))

	return returnedHostSet, plg, nil
}

// UpdateSet updates the repository for host set entry s with the
// values populated, for the fields listed in fieldMask. It returns a
// new HostSet containing the updated values, the hosts in the set,
// and a count of the number of records updated. s is not changed.
//
// s must contain a valid PublicId and CatalogId. Name, Description,
// Attributes, and PreferredEndpoints can be updated. Name must be
// unique among all sets associated with a single catalog.
//
// An attribute of s will be set to NULL in the database if the
// attribute in s is the zero value and it is included in fieldMask.
// Note that this does not apply to s.Attributes - a null
// s.Attributes is a no-op for modifications. Rather, if fields need
// to be reset, its field in c.Attributes should individually set to
// null.
//
// Updates are sent to OnUpdateSet with a full copy of both the
// current set, the state of the new set should it be updated, along
// with its parent host catalog and persisted state (can include
// secrets). This is a stateless call and does not affect the final
// record written, but some plugins may perform some actions on this
// call. Update of the record in the database is aborted if this call
// fails.
func (r *Repository) UpdateSet(ctx context.Context, projectId string, s *HostSet, version uint32, fieldMask []string, opt ...Option) (*HostSet, []*Host, *plugin.Plugin, int, error) {
	const op = "plugin.(Repository).UpdateSet"
	if s == nil {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil HostSet")
	}
	if s.HostSet == nil {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil embedded HostSet")
	}
	if s.PublicId == "" {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	if projectId == "" {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}
	if len(fieldMask) == 0 {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "empty field mask")
	}

	// Get the old set first. We patch the record first before
	// sending it to the DB for updating so that we can run on
	// OnUpdateSet. Note that the field masks are still used for
	// updating.
	sets, plg, err := r.getSets(ctx, s.PublicId, "")
	if err != nil {
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	if len(sets) == 0 {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("host set id %q not found", s.PublicId))
	}

	if len(sets) != 1 {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.Internal, op, fmt.Sprintf("unexpected amount of sets found, want=1, got=%d", len(sets)))
	}

	currentSet := sets[0]

	// Assert the version of the current set to make sure we're
	// updating the correct one.
	if currentSet.GetVersion() != version {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.VersionMismatch, op, fmt.Sprintf("set version mismatch, want=%d, got=%d", currentSet.GetVersion(), version))
	}

	// Clone the set so that we can set fields.
	newSet := currentSet.clone()
	var updateAttributes bool
	var updateSyncInterval bool
	var dbMask, nullFields []string
	const (
		endpointOpNoop   = "endpointOpNoop"
		endpointOpDelete = "endpointOpDelete"
		endpointOpUpdate = "endpointOpUpdate"
	)
	var endpointOp string = endpointOpNoop
	for _, f := range fieldMask {
		switch {
		case strings.EqualFold("name", f) && s.Name == "":
			nullFields = append(nullFields, "name")
			newSet.Name = s.Name
		case strings.EqualFold("name", f) && s.Name != "":
			dbMask = append(dbMask, "name")
			newSet.Name = s.Name
		case strings.EqualFold("description", f) && s.Description == "":
			nullFields = append(nullFields, "description")
			newSet.Description = s.Description
		case strings.EqualFold("description", f) && s.Description != "":
			dbMask = append(dbMask, "description")
			newSet.Description = s.Description
		case strings.EqualFold("SyncIntervalSeconds", f) && s.SyncIntervalSeconds == 0:
			nullFields = append(nullFields, "SyncIntervalSeconds")
			newSet.SyncIntervalSeconds = s.SyncIntervalSeconds
			updateSyncInterval = true
		case strings.EqualFold("SyncIntervalSeconds", f) && s.SyncIntervalSeconds != 0:
			dbMask = append(dbMask, "SyncIntervalSeconds")
			newSet.SyncIntervalSeconds = s.SyncIntervalSeconds
			updateSyncInterval = true
		case strings.EqualFold("PreferredEndpoints", f) && len(s.PreferredEndpoints) == 0:
			endpointOp = endpointOpDelete
			newSet.PreferredEndpoints = s.PreferredEndpoints
		case strings.EqualFold("PreferredEndpoints", f) && len(s.PreferredEndpoints) != 0:
			endpointOp = endpointOpUpdate
			newSet.PreferredEndpoints = s.PreferredEndpoints
		case strings.EqualFold("attributes", strings.Split(f, ".")[0]):
			// Flag attributes for updating. While multiple masks may be
			// sent, we only need to do this once.
			updateAttributes = true

		default:
			return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}

	if updateAttributes {
		dbMask = append(dbMask, "attributes")
		newSet.Attributes, err = patchstruct.PatchBytes(newSet.Attributes, s.Attributes)
		if err != nil {
			return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("error in set attribute JSON"))
		}

		// Flag the record as needing a sync since we've updated
		// attributes.
		dbMask = append(dbMask, "NeedSync")
		newSet.NeedSync = true
	}

	// Get the host catalog for the set and its persisted data.
	catalog, persisted, err := r.getCatalog(ctx, newSet.CatalogId)
	if err != nil {
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error looking up catalog with id %q", newSet.CatalogId)))
	}

	// Assert that the catalog project ID and supplied project ID match.
	if catalog.ProjectId != projectId {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("catalog id %q not in project id %q", newSet.CatalogId, projectId))
	}

	// Convert the catalog values to API protobuf values, which is what
	// we use for the plugin hook calls.
	plgHc, err := toPluginCatalog(ctx, catalog, plg)
	if err != nil {
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	currentPlgSet, err := toPluginSet(ctx, currentSet)
	if err != nil {
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	newPlgSet, err := toPluginSet(ctx, newSet)
	if err != nil {
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	plgClient, err := pluginClientFactoryFn(ctx, plgHc, r.plugins)
	if err != nil {
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	if updateAttributes {
		if newPlgSet.GetAttributes() != nil {
			if err := normalizeSetAttributes(ctx, plgClient, plgHc, newPlgSet); err != nil {
				return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}
			if newSet.Attributes, err = proto.Marshal(newPlgSet.GetAttributes()); err != nil {
				return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}
		}
	}

	// Get the preferred endpoints to write out.
	var preferredEndpoints []*host.PreferredEndpoint
	if endpointOp == endpointOpUpdate {
		preferredEndpoints = make([]*host.PreferredEndpoint, 0, len(newSet.PreferredEndpoints))
		for i, e := range newSet.PreferredEndpoints {
			obj, err := host.NewPreferredEndpoint(ctx, newSet.PublicId, uint32(i+1), e)
			if err != nil {
				return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}
			preferredEndpoints = append(preferredEndpoints, obj)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	// If the call to the plugin succeeded, we do not want to call it again if
	// the transaction failed and is being retried.
	var pluginCalledSuccessfully bool

	var setUpdated, preferredEndpointsUpdated bool
	var returnedSet *HostSet
	var hosts []*Host
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			returnedSet = newSet.clone()
			msgs := make([]*oplog.Message, 0, len(preferredEndpoints)+len(currentSet.PreferredEndpoints)+2)
			ticket, err := w.GetTicket(ctx, s)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			if len(dbMask) != 0 || len(nullFields) != 0 {
				var hsOplogMsg oplog.Message
				numUpdated, err := w.Update(
					ctx,
					returnedSet,
					dbMask,
					nullFields,
					db.NewOplogMsg(&hsOplogMsg),
					db.WithVersion(&version),
				)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}

				if numUpdated != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("expected 1 set to be updated, got %d", numUpdated))
				}

				setUpdated = true
				msgs = append(msgs, &hsOplogMsg)
			}

			switch endpointOp {
			case endpointOpDelete, endpointOpUpdate:
				if len(currentSet.PreferredEndpoints) > 0 {
					// Delete all old endpoint entries.
					var peps []*host.PreferredEndpoint
					for i := 1; i <= len(currentSet.PreferredEndpoints); i++ {
						p := host.AllocPreferredEndpoint()
						p.HostSetId, p.Priority = currentSet.GetPublicId(), uint32(i)
						peps = append(peps, p)
					}
					deleteOplogMsgs := make([]*oplog.Message, 0, len(peps))
					if _, err := w.DeleteItems(ctx, peps, db.WithDebug(true), db.NewOplogMsgs(&deleteOplogMsgs)); err != nil {
						return errors.Wrap(ctx, err, op)
					}
					// Only append the oplog message if an operation was actually
					// performed.
					if len(deleteOplogMsgs) > 0 {
						preferredEndpointsUpdated = true
						msgs = append(msgs, deleteOplogMsgs...)
					}
				}
			}
			if endpointOp == endpointOpUpdate {
				// Create the new entries.
				peCreateOplogMsgs := make([]*oplog.Message, 0, len(preferredEndpoints))
				if err := w.CreateItems(ctx, preferredEndpoints, db.NewOplogMsgs(&peCreateOplogMsgs)); err != nil {
					return err
				}

				preferredEndpointsUpdated = true
				msgs = append(msgs, peCreateOplogMsgs...)
			}

			if !setUpdated && preferredEndpointsUpdated {
				returnedSet.Version = uint32(version) + 1
				var hsOplogMsg oplog.Message
				numUpdated, err := w.Update(
					ctx,
					returnedSet,
					[]string{"version"},
					[]string{},
					db.NewOplogMsg(&hsOplogMsg),
					db.WithVersion(&version),
				)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}

				if numUpdated != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("expected 1 set to be updated, got %d", numUpdated))
				}

				msgs = append(msgs, &hsOplogMsg)
			}

			if len(msgs) != 0 {
				metadata := s.oplog(oplog.OpType_OP_TYPE_UPDATE)
				if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
				}
			}

			hsAgg := &hostSetAgg{PublicId: currentSet.GetPublicId()}
			if err := reader.LookupByPublicId(ctx, hsAgg); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("looking up host after update"))
			}
			returnedSet, err = hsAgg.toHostSet(ctx)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("converting from host aggregate to host after update"))
			}

			if !pluginCalledSuccessfully {
				_, err = plgClient.OnUpdateSet(ctx, &plgpb.OnUpdateSetRequest{
					CurrentSet: currentPlgSet,
					NewSet:     newPlgSet,
					Catalog:    plgHc,
					Persisted:  persisted,
				})
				if err != nil {
					if status.Code(err) != codes.Unimplemented {
						return errors.Wrap(ctx, err, op)
					}
				}
			}

			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s: name %s already exists", newSet.PublicId, newSet.Name)))
		}
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s", newSet.PublicId)))
	}

	hosts, err = listHostBySetIds(ctx, r.reader, []string{returnedSet.PublicId}, opt...)
	if err != nil {
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	var numUpdated int
	if setUpdated || preferredEndpointsUpdated {
		numUpdated = 1
	}

	switch {
	case updateAttributes:
		// Request a host sync since we have updated attributes.
		_ = r.scheduler.UpdateJobNextRunInAtLeast(ctx, setSyncJobName, 0, scheduler.WithRunNow(true))
	case updateSyncInterval:
		var schOpt []scheduler.Option
		tilNextSync := time.Until(returnedSet.LastSyncTime.AsTime().Add(time.Duration(returnedSet.SyncIntervalSeconds) * time.Second))
		if tilNextSync <= 0 {
			tilNextSync = 0
			schOpt = append(schOpt, scheduler.WithRunNow(true))
		}
		_ = r.scheduler.UpdateJobNextRunInAtLeast(ctx, setSyncJobName, tilNextSync, schOpt...)
	}

	return returnedSet, hosts, plg, numUpdated, nil
}

// LookupSet will look up a host set in the repository and return the host set,
// as well as host IDs that match. If the host set is not found, it will return
// nil, nil, nil. No options are currently supported.
func (r *Repository) LookupSet(ctx context.Context, publicId string, _ ...Option) (*HostSet, *plugin.Plugin, error) {
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

// listSets returns a slice of HostSets for the catalogId.
// Supported options:
//   - WithLimit which overrides the limit set in the Repository object
//   - WithStartPageAfterItem which sets where to start listing from
func (r *Repository) listSets(ctx context.Context, catalogId string, opt ...Option) ([]*HostSet, *plugin.Plugin, time.Time, error) {
	const op = "plugin.(Repository).listSets"
	if catalogId == "" {
		return nil, nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing catalog id")
	}

	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	query := fmt.Sprintf(listSetsTemplate, limit)
	args := []any{sql.Named("catalog_id", catalogId)}
	if opts.withStartPageAfterItem != nil {
		query = fmt.Sprintf(listSetsPageTemplate, limit)
		args = append(args,
			sql.Named("last_item_create_time", opts.withStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	return r.querySets(ctx, query, args)
}

// listSetsRefresh returns a slice of Host sets for the catalogId and the associated plugin.
// Supported options:
//   - WithLimit which overrides the limit set in the Repository object
//   - WithStartPageAfterItem which sets where to start listing from
func (r *Repository) listSetsRefresh(ctx context.Context, catalogId string, updatedAfter time.Time, opt ...Option) ([]*HostSet, *plugin.Plugin, time.Time, error) {
	const op = "plugin.(Repository).listSetsRefresh"
	switch {
	case catalogId == "":
		return nil, nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	case updatedAfter.IsZero():
		return nil, nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	query := fmt.Sprintf(listSetsRefreshTemplate, limit)
	args := []any{
		sql.Named("catalog_id", catalogId),
		sql.Named("updated_after_time", updatedAfter),
	}
	if opts.withStartPageAfterItem != nil {
		query = fmt.Sprintf(listSetsRefreshPageTemplate, limit)
		args = append(args,
			sql.Named("last_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	return r.querySets(ctx, query, args)
}

func (r *Repository) querySets(ctx context.Context, query string, args []any) ([]*HostSet, *plugin.Plugin, time.Time, error) {
	const op = "plugin.(Repository).querySets"

	var sets []*HostSet
	var plg *plugin.Plugin
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		rows, err := r.Query(ctx, query, args)
		if err != nil {
			return err
		}
		defer rows.Close()
		var foundSets []*hostSetAgg
		for rows.Next() {
			if err := r.ScanRows(ctx, rows, &foundSets); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(foundSets) != 0 {
			plg = plugin.NewPlugin()
			plg.PublicId = foundSets[0].PluginId
			if err := r.LookupByPublicId(ctx, plg); err != nil {
				return err
			}
			sets = make([]*HostSet, 0, len(foundSets))
			for _, ha := range foundSets {
				set, err := ha.toHostSet(ctx)
				if err != nil {
					return err
				}
				sets = append(sets, set)
			}
		}
		transactionTimestamp, err = r.Now(ctx)
		return err
	}); err != nil {
		return nil, nil, time.Time{}, errors.Wrap(ctx, err, op)
	}
	return sets, plg, transactionTimestamp, nil
}

// DeleteSet deletes the host set for the provided id from the repository
// returning a count of the number of records deleted. All options are
// ignored.
func (r *Repository) DeleteSet(ctx context.Context, projectId string, publicId string, _ ...Option) (int, error) {
	const op = "plugin.(Repository).DeleteSet"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	if projectId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no project id")
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

	plgHc, err := toPluginCatalog(ctx, c, plg)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	plgHs, err := toPluginSet(ctx, s)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}

	plgClient, err := pluginClientFactoryFn(ctx, plgHc, r.plugins)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}

	// Even if the plugin returns an error, we ignore it and proceed with
	// deleting the set, hence we don't check the error here. This is because we
	// may get errors from the plugin that we can't do anything about (say, it's
	// already deleted) and we still want to delete the set from the database.
	_, _ = plgClient.OnDeleteSet(ctx, &plgpb.OnDeleteSetRequest{Catalog: plgHc, Persisted: p, Set: plgHs})

	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
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

func (r *Repository) getSets(ctx context.Context, publicId string, catalogId string, opt ...host.Option) ([]*HostSet, *plugin.Plugin, error) {
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

	reader := r.reader
	writer := r.writer
	if !util.IsNil(opts.WithReader) {
		reader = opts.WithReader
	}
	if !util.IsNil(opts.WithWriter) {
		writer = opts.WithWriter
	}

	args := make([]any, 0, 1)
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
	if err := reader.SearchWhere(ctx, &aggHostSets, where, args, dbArgs...); err != nil {
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
	var plg *plugin.Plugin
	if plgId != "" {
		plg, err = r.getPlugin(ctx, plgId, WithReaderWriter(reader, writer))
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

	var name, description *wrapperspb.StringValue
	if inName := in.GetName(); inName != "" {
		name = wrapperspb.String(inName)
	}
	if inDescription := in.GetDescription(); inDescription != "" {
		description = wrapperspb.String(inDescription)
	}

	hs := &pb.HostSet{
		Id:                 in.GetPublicId(),
		Name:               name,
		Description:        description,
		PreferredEndpoints: in.PreferredEndpoints,
	}
	if in.GetAttributes() != nil {
		attrs := &structpb.Struct{}
		if err := proto.Unmarshal(in.GetAttributes(), attrs); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to marshal attributes"))
		}
		hs.Attrs = &pb.HostSet_Attributes{
			Attributes: attrs,
		}
	}
	return hs, nil
}

// listDeletedSetIds lists the public IDs of any hosts deleted since the timestamp provided,
// and the timestamp of the transaction within which the hosts were listed.
func (r *Repository) listDeletedSetIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "static.(Repository).listDeletedHostSetIds"
	var deleteHostSets []*deletedHostSet
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, _ db.Writer) error {
		if err := r.SearchWhere(ctx, &deleteHostSets, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted host sets"))
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	var hostSetIds []string
	for _, t := range deleteHostSets {
		hostSetIds = append(hostSetIds, t.PublicId)
	}
	return hostSetIds, transactionTimestamp, nil
}

// estimatedSetCount returns an estimate of the total number of plugin host sets.
func (r *Repository) estimatedSetCount(ctx context.Context) (int, error) {
	const op = "plugin.(Repository).estimatedHostSetCount"
	rows, err := r.reader.Query(ctx, estimateCountHostSets, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query plugin host sets"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query plugin host sets"))
		}
	}
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query plugin host sets"))
	}
	return count, nil
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
	if err := r.reader.SearchWhere(ctx, &setAggs, "public_id in (?)", []any{setIds}); err != nil {
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
	if err := r.reader.SearchWhere(ctx, &setMembers, "set_id in (?)", []any{setIds}); err != nil {
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
	if err := r.reader.SearchWhere(ctx, &hostAggs, "public_id in (?)", []any{hostIds}); err != nil {
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
			pref, err := endpoint.NewPreferencer(ctx, endpoint.WithPreferenceOrder(s.PreferredEndpoints))
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("getting preferencer for set %q", sId)))
			}
			var opts []endpoint.Option
			if len(h.GetIpAddresses()) > 0 {
				opts = append(opts, endpoint.WithIpAddrs(h.GetIpAddresses()))
			}
			if len(h.GetDnsNames()) > 0 {
				opts = append(opts, endpoint.WithDnsNames(h.GetDnsNames()))
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
