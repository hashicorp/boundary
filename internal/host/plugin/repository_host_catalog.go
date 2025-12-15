// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/patchstruct"
	"github.com/hashicorp/boundary/internal/oplog"
	plg "github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/util"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	pbset "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/mr-tron/base58"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// normalizeCatalogAttributes allows a plugin to normalize attributes before
// they are saved
func normalizeCatalogAttributes(ctx context.Context, plgClient plgpb.HostPluginServiceClient, plgHc *pb.HostCatalog) error {
	const op = "plugin.(Repository).normalizeCatalogAttributes"
	switch {
	case util.IsNil(plgClient):
		return errors.New(ctx, errors.InvalidParameter, op, "plugin client is nil")
	case plgHc == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "host catalog is nil")
	case plgHc.GetWorkerFilter().GetValue() != "" && plgHc.GetPlugin() == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "plugin data is not available on host catalog with worker filter")
	case plgHc.GetAttributes() == nil:
		return nil
	}

	ret, err := plgClient.NormalizeCatalogData(ctx, &plgpb.NormalizeCatalogDataRequest{
		Attributes: plgHc.GetAttributes(),
		Plugin:     plgHc.GetPlugin(),
	})
	switch {
	case err == nil:
		// TODO: this should be updated to return these attributes rather than updating them in-place
		if ret.Attributes != nil {
			plgHc.Attrs = &pb.HostCatalog_Attributes{
				Attributes: ret.Attributes,
			}
		}
	case status.Code(err) == codes.Unimplemented:
		// Do nothing
	default:
		return errors.Wrap(ctx, err, op, errors.WithMsg("error asking plugin to normalize catalog data"))
	}

	return nil
}

// CreateCatalog inserts c into the repository and returns a new
// HostCatalog containing the catalog's PublicId. c must contain a valid
// ProjectID and PluginID. c must not contain a PublicId. The PublicId is
// generated and assigned by this method. opt is ignored.
//
// c.Secret, c.Name and c.Description are optional. If c.Name is set, it must be
// unique within c.ProjectId.  If c.Secret is set, it will be stored encrypted but
// not included in the returned *HostCatalog.
//
// Both c.CreateTime and c.UpdateTime are ignored.
func (r *Repository) CreateCatalog(ctx context.Context, c *HostCatalog, _ ...Option) (*HostCatalog, *plg.Plugin, error) {
	const op = "plugin.(Repository).CreateCatalog"
	if c == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "nil HostCatalog")
	}
	if c.HostCatalog == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "nil embedded HostCatalog")
	}
	if c.ProjectId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}
	if c.PublicId != "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	if c.PluginId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no plugin id")
	}
	if c.Attributes == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "nil attributes")
	}
	c = c.clone()
	id, err := newHostCatalogId(ctx)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	c.PublicId = id

	// Use PatchBytes' functionality that does not add keys where the values
	// are nil to the resulting struct since we do not want to store nil valued
	// attributes.
	c.Attributes, err = patchstruct.PatchBytes([]byte{}, c.Attributes)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, c.ProjectId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	// If secrets were passed in, HMAC 'em
	if c.Secrets != nil && len(c.Secrets.GetFields()) > 0 {
		if err := c.hmacSecrets(ctx, databaseWrapper); err != nil {
			return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("error hmac'ing passed-in secrets"))
		}
	}

	plg, err := r.getPlugin(ctx, c.GetPluginId())
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	plgHc, err := toPluginCatalog(ctx, c, plg)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	plgClient, err := pluginClientFactoryFn(ctx, plgHc, r.plugins)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	if plgHc.GetAttributes() != nil {
		if err := normalizeCatalogAttributes(ctx, plgClient, plgHc); err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		if c.Attributes, err = proto.Marshal(plgHc.GetAttributes()); err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, c.ProjectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	// If the call to the plugin succeeded, we do not want to call it again if
	// the transaction failed and is being retried.
	var pluginCalledSuccessfully bool
	var plgResp *plgpb.OnCreateCatalogResponse

	var newHostCatalog *HostCatalog
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 3)
			ticket, err := w.GetTicket(ctx, c)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			newHostCatalog = c.clone()
			var cOplogMsg oplog.Message
			if err := w.Create(ctx, newHostCatalog, db.NewOplogMsg(&cOplogMsg)); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			msgs = append(msgs, &cOplogMsg)

			if !pluginCalledSuccessfully {
				plgResp, err = plgClient.OnCreateCatalog(ctx, &plgpb.OnCreateCatalogRequest{Catalog: plgHc})
				if err != nil {
					if status.Code(err) != codes.Unimplemented {
						return errors.Wrap(ctx, err, op)
					}
				}
				pluginCalledSuccessfully = true
			}

			if len(plgResp.GetPersisted().GetSecrets().GetFields()) > 0 {
				hcSecret, err := newHostCatalogSecret(ctx, id, plgResp.GetPersisted().GetSecrets())
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if err := hcSecret.encrypt(ctx, databaseWrapper); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if hcSecret != nil {
					newSecret := hcSecret.clone()
					var sOplogMsg oplog.Message
					if err := w.Create(ctx, newSecret, db.NewOplogMsg(&sOplogMsg)); err != nil {
						return errors.Wrap(ctx, err, op)
					}
					msgs = append(msgs, &sOplogMsg)
				}
			}

			metadata := c.oplog(oplog.OpType_OP_TYPE_CREATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in project: %s: name %s already exists", c.ProjectId, c.Name)))
		}
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in project: %s", c.ProjectId)))
	}
	return newHostCatalog, plg, nil
}

// UpdateCatalog updates the repository entry for c.PublicId with the
// values in c for the fields listed in fieldMask. It returns a new
// HostCatalog containing the updated values and a count of the number of
// records updated. c is not changed.
//
// c must contain a valid PublicId. c.Name, c.Description, and
// c.Attributes can be updated; if c.Secrets is present, its contents
// are sent to the plugin (along with any other changes, see below)
// before the update is sent to the database.
//
// An attribute of c will be set to NULL in the database if the
// attribute in c is the zero value and it is included in fieldMask.
// Note that this does not apply to c.Attributes - a null
// c.Attributes is a no-op for modifications. Rather, if fields need
// to be reset, its field in c.Attributes should individually set to
// null.
//
// Updates are sent to OnUpdateCatalog with a full copy of both the
// current catalog, and the state of the new catalog should it be
// updated, along with any secrets included in the new request. This
// request may alter the returned persisted state. Update of the
// record in the database is aborted if this call fails.
func (r *Repository) UpdateCatalog(ctx context.Context, c *HostCatalog, version uint32, fieldMask []string, _ ...Option) (*HostCatalog, *plg.Plugin, int, error) {
	const op = "plugin.(Repository).UpdateCatalog"
	if c == nil {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil HostCatalog")
	}
	if c.HostCatalog == nil {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil embedded HostCatalog")
	}
	if c.PublicId == "" {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	if c.ProjectId == "" {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}
	if len(fieldMask) == 0 {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "empty field mask")
	}

	// Get the old catalog first. We patch the record first before
	// sending it to the DB for updating so that we can run on
	// OnUpdateCatalog. Note that the field masks are still used for
	// updating.
	currentCatalog, currentCatalogPersisted, err := r.getCatalog(ctx, c.PublicId)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error looking up catalog with id %q", c.PublicId)))
	}

	if currentCatalog == nil {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("catalog with id %q not found", c.PublicId))
	}

	// Assert the version of the current catalog to make sure we're
	// updating the correct one.
	if currentCatalog.GetVersion() != version {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.VersionMismatch, op, fmt.Sprintf("catalog version mismatch, want=%d, got=%d", currentCatalog.GetVersion(), version))
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, c.ProjectId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}

	// Clone the catalog so that we can set fields.
	newCatalog := currentCatalog.clone()
	var updateAttributes bool
	var dbMask, nullFields []string
	var alreadySetSecrets bool
	for _, f := range fieldMask {
		switch {
		case strings.EqualFold("name", f) && c.Name == "":
			nullFields = append(nullFields, "name")
			newCatalog.Name = c.Name
		case strings.EqualFold("name", f) && c.Name != "":
			dbMask = append(dbMask, "name")
			newCatalog.Name = c.Name
		case strings.EqualFold("description", f) && c.Description == "":
			nullFields = append(nullFields, "description")
			newCatalog.Description = c.Description
		case strings.EqualFold("description", f) && c.Description != "":
			dbMask = append(dbMask, "description")
			newCatalog.Description = c.Description
		case strings.EqualFold("attributes", strings.Split(f, ".")[0]):
			// Flag attributes for updating. While multiple masks may be
			// sent, we only need to do this once.
			updateAttributes = true
		case strings.EqualFold("secrets", strings.Split(f, ".")[0]):
			if alreadySetSecrets {
				continue
			}
			alreadySetSecrets = true
			// While in a similar format, secrets are passed along
			// wholesale (for the time being). Don't append this mask
			// field, as secrets do not have a database entry.
			newCatalog.Secrets = c.Secrets
			switch {
			case newCatalog.Secrets == nil,
				len(newCatalog.Secrets.GetFields()) == 0:
				nullFields = append(nullFields, "SecretsHmac")
			default:
				// If secrets were passed in, HMAC 'em
				if err := newCatalog.hmacSecrets(ctx, databaseWrapper); err != nil {
					return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("error hmac'ing passed-in secrets"))
				}
				dbMask = append(dbMask, "SecretsHmac")
			}
		case strings.EqualFold("WorkerFilter", f) && c.WorkerFilter == "":
			nullFields = append(nullFields, "WorkerFilter")
			newCatalog.WorkerFilter = c.WorkerFilter
		case strings.EqualFold("WorkerFilter", f) && c.WorkerFilter != "":
			dbMask = append(dbMask, "WorkerFilter")
			newCatalog.WorkerFilter = c.WorkerFilter
		default:
			return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}

	var needSetSync, runSyncJob bool
	if updateAttributes {
		dbMask = append(dbMask, "attributes")
		newCatalog.Attributes, err = patchstruct.PatchBytes(newCatalog.Attributes, c.Attributes)
		if err != nil {
			return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("error in catalog attribute JSON"))
		}

		// Flag for host sets under this catalog to be synced.
		needSetSync = true
	}

	// Get the plugin for the host catalog - this is to return it back after the
	// update is complete, as well as forwarding it to the actual plugin given
	// that it is necessary if we're using a worker filter. Fetch it here so
	// that if there's an integrity error, we don't call the plugin.
	plg, err := r.getPlugin(ctx, currentCatalog.GetPluginId())
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	// Convert the catalog values to API protobuf values, which is what
	// we use for the plugin hook calls.
	currPlgHc, err := toPluginCatalog(ctx, currentCatalog, plg)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	newPlgHc, err := toPluginCatalog(ctx, newCatalog, plg)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	plgClient, err := pluginClientFactoryFn(ctx, newPlgHc, r.plugins)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	if updateAttributes {
		if newPlgHc.GetAttributes() != nil {
			if err := normalizeCatalogAttributes(ctx, plgClient, newPlgHc); err != nil {
				return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}
			if newCatalog.Attributes, err = proto.Marshal(newPlgHc.GetAttributes()); err != nil {
				return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}
		}
	}

	// Get the oplog.
	oplogWrapper, err := r.kms.GetWrapper(ctx, newCatalog.ProjectId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var pluginCalledSuccessfully bool
	var plgResp *plgpb.OnUpdateCatalogResponse

	var recordUpdated bool
	var returnedCatalog *HostCatalog
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 3)
			ticket, err := w.GetTicket(ctx, newCatalog)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			if len(dbMask) != 0 || len(nullFields) != 0 {
				returnedCatalog = newCatalog.clone()
				var cOplogMsg oplog.Message
				catalogsUpdated, err := w.Update(
					ctx,
					returnedCatalog,
					dbMask,
					nullFields,
					db.NewOplogMsg(&cOplogMsg),
					db.WithVersion(&version),
				)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if catalogsUpdated != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("expected 1 catalog to be deleted, got %d", catalogsUpdated))
				}
				msgs = append(msgs, &cOplogMsg)
				recordUpdated = true
			} else {
				// Returned catalog needs to be the old copy, as no fields in the
				// catalog itself are being updated (note: secrets may still be
				// updated).
				returnedCatalog = currentCatalog.clone()
			}

			if !pluginCalledSuccessfully {
				plgResp, err = plgClient.OnUpdateCatalog(ctx, &plgpb.OnUpdateCatalogRequest{
					CurrentCatalog: currPlgHc,
					NewCatalog:     newPlgHc,
					Persisted:      currentCatalogPersisted,
				})
				if err != nil {
					if status.Code(err) != codes.Unimplemented {
						return errors.Wrap(ctx, err, op)
					}
				}
				pluginCalledSuccessfully = true
			}
			var updatedPersisted bool
			if plgResp != nil && plgResp.GetPersisted().GetSecrets() != nil {
				if len(plgResp.GetPersisted().GetSecrets().GetFields()) == 0 {
					// Flag the secret to be deleted if it exists.
					hcSecret, err := newHostCatalogSecret(ctx, currentCatalog.GetPublicId(), plgResp.GetPersisted().GetSecrets())
					if err != nil {
						return errors.Wrap(ctx, err, op)
					}
					// We didn't set/encrypt the persisted data because there was
					// none returned. Just delete the entry.
					deletedSecret := hcSecret.clone()
					var sOplogMsg oplog.Message
					secretsDeleted, err := w.Delete(ctx, deletedSecret, db.NewOplogMsg(&sOplogMsg))
					if err != nil {
						return errors.Wrap(ctx, err, op)
					}
					if secretsDeleted > 1 {
						return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("expected 0 or 1 catalog secret to be deleted, got %d", secretsDeleted))
					}
					if secretsDeleted == 1 {
						updatedPersisted = true
						msgs = append(msgs, &sOplogMsg)
					}
				} else {
					hcSecret, err := newHostCatalogSecret(ctx, currentCatalog.GetPublicId(), plgResp.GetPersisted().GetSecrets())
					if err != nil {
						return errors.Wrap(ctx, err, op)
					}
					if err := hcSecret.encrypt(ctx, databaseWrapper); err != nil {
						return errors.Wrap(ctx, err, op)
					}

					// Update the secrets.
					updatedSecret := hcSecret.clone()
					var sOplogMsg oplog.Message
					if err := w.Create(
						ctx,
						updatedSecret,
						db.WithOnConflict(&db.OnConflict{
							Target: db.Columns{"catalog_id"},
							Action: db.SetColumns([]string{"secret", "key_id"}),
						}),
						db.NewOplogMsg(&sOplogMsg),
					); err != nil {
						return errors.Wrap(ctx, err, op)
					}
					updatedPersisted = true
					msgs = append(msgs, &sOplogMsg)
				}
			}

			if !recordUpdated && updatedPersisted {
				// we only updated secrets, so we need to increment the
				// version of the host catalog manually.
				returnedCatalog = newCatalog.clone()
				returnedCatalog.Version = uint32(version) + 1
				var cOplogMsg oplog.Message
				catalogsUpdated, err := w.Update(
					ctx,
					returnedCatalog,
					[]string{"version"},
					[]string{},
					db.NewOplogMsg(&cOplogMsg),
					db.WithVersion(&version),
				)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if catalogsUpdated != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("expected 1 catalog to be updated, got %d", catalogsUpdated))
				}
				msgs = append(msgs, &cOplogMsg)
				recordUpdated = true
			}

			if needSetSync {
				// We also need to mark all host sets in this catalog to be
				// synced as well.
				setsForCatalog, _, err := r.getSets(ctx, "", returnedCatalog.PublicId, host.WithReaderWriter(read, w))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get sets for host catalog"))
				}

				for _, set := range setsForCatalog {
					newSet := set.clone()
					newSet.NeedSync = true
					var msg oplog.Message
					n, err := w.Update(ctx, newSet, []string{"NeedSync"}, []string{}, db.NewOplogMsg(&msg))
					if err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update host set"))
					}

					if n > 1 {
						return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("expected no more than 1 host set to be updated while flagging host set id %q for synchronization, got %d", newSet.PublicId, n))
					}

					msgs = append(msgs, &msg)
					runSyncJob = true
				}
			}

			if len(msgs) != 0 {
				metadata := newCatalog.oplog(oplog.OpType_OP_TYPE_UPDATE)
				if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
				}
			}

			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s: name %s already exists", newCatalog.PublicId, newCatalog.Name)))
		}
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s", newCatalog.PublicId)))
	}

	if runSyncJob {
		_ = r.scheduler.UpdateJobNextRunInAtLeast(ctx, setSyncJobName, 0, scheduler.WithRunNow(true))
	}

	// Even if we didn't update any records, if we were able to find the record
	// with the appropriate version, returning 1 row updated is consistent with
	// static's update catalog behavior.
	numUpdated := 1

	return returnedCatalog, plg, numUpdated, nil
}

// LookupCatalog returns the HostCatalog for id. Returns nil, nil if no
// HostCatalog is found for id.
func (r *Repository) LookupCatalog(ctx context.Context, id string, _ ...Option) (*HostCatalog, *plg.Plugin, error) {
	const op = "plugin.(Repository).LookupCatalog"
	if id == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	c, _, err := r.getCatalog(ctx, id)
	if errors.IsNotFoundError(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", id)))
	}
	plg, err := r.getPlugin(ctx, c.GetPluginId())
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return c, plg, nil
}

// DeleteCatalog deletes catalog for the provided id from the repository
// returning a count of the number of records deleted. All options are ignored.
func (r *Repository) DeleteCatalog(ctx context.Context, id string, _ ...Option) (int, error) {
	const op = "plugin.(Repository).DeleteCatalog"
	if id == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}

	c, p, err := r.getCatalog(ctx, id)
	if err != nil && !errors.IsNotFoundError(err) {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	if c == nil {
		return db.NoRowsAffected, nil
	}

	plg, err := r.getPlugin(ctx, c.GetPluginId())
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	plgHc, err := toPluginCatalog(ctx, c, plg)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	sets, _, err := r.getSets(ctx, "", c.GetPublicId())
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	var plgSets []*pbset.HostSet
	for _, s := range sets {
		ps, err := toPluginSet(ctx, s)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		plgSets = append(plgSets, ps)
	}

	plgClient, err := pluginClientFactoryFn(ctx, plgHc, r.plugins)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	_, err = plgClient.OnDeleteCatalog(ctx, &plgpb.OnDeleteCatalogRequest{
		Catalog:   plgHc,
		Sets:      plgSets,
		Persisted: p,
	})
	if err != nil {
		// Even if the plugin returns an error, we ignore it and proceed with
		// deleting the catalog.
		event.WriteError(ctx, op, err, event.WithInfoMsg("plugin deleting catalog", "host plugin id", c.GetPluginId()))
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, c.ProjectId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	metadata := c.oplog(oplog.OpType_OP_TYPE_DELETE)

	var rowsDeleted int
	var deleteCatalog *HostCatalog
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteCatalog = c.clone()
			var err error
			rowsDeleted, err = w.Delete(
				ctx,
				deleteCatalog,
				db.WithOplog(oplogWrapper, metadata),
			)
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
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("delete failed for %s", c.PublicId)))
	}

	return rowsDeleted, nil
}

// getCatalog retrieves the *HostCatalog with the provided id.  If it is not found or there
// is an problem getting it from the database an error is returned instead.
func (r *Repository) getCatalog(ctx context.Context, id string) (*HostCatalog, *plgpb.HostCatalogPersisted, error) {
	const op = "plugin.(Repository).getCatalog"
	ca := &catalogAgg{}
	ca.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, ca); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", id)))
	}
	c, s := ca.toCatalogAndPersisted()
	var p *plgpb.HostCatalogPersisted
	if s != nil {
		var err error
		p, err = toPluginPersistedData(ctx, r.kms, c.GetProjectId(), s)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
	}
	return c, p, nil
}

func (r *Repository) getPlugin(ctx context.Context, plgId string, opts ...Option) (*plg.Plugin, error) {
	const op = "plugin.(Repository).getPlugin"
	if plgId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no plugin id")
	}
	opt := getOpts(opts...)
	reader := r.reader
	if !util.IsNil(opt.WithReader) {
		reader = opt.WithReader
	}
	plg := plg.NewPlugin()
	plg.PublicId = plgId
	if err := reader.LookupByPublicId(ctx, plg); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get host plugin with id %q", plgId)))
	}
	return plg, nil
}

// toPluginCatalog returns a host catalog, with it's secret if available, in the format expected
// by the host plugin system.
func toPluginCatalog(ctx context.Context, in *HostCatalog, plg *plg.Plugin) (*pb.HostCatalog, error) {
	const op = "plugin.toPluginCatalog"
	if in == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil storage plugin")
	}
	var name, description, workerFilter *wrapperspb.StringValue
	if inName := in.GetName(); inName != "" {
		name = wrapperspb.String(inName)
	}
	if inDescription := in.GetDescription(); inDescription != "" {
		description = wrapperspb.String(inDescription)
	}
	if inWorkerFilter := in.GetWorkerFilter(); inWorkerFilter != "" {
		workerFilter = wrapperspb.String(inWorkerFilter)
	}

	hc := &pb.HostCatalog{
		Id:           in.GetPublicId(),
		ScopeId:      in.GetProjectId(),
		Name:         name,
		Description:  description,
		WorkerFilter: workerFilter,
		PluginId:     in.GetPluginId(),
		Plugin:       toPluginInfo(plg),
	}
	if len(in.GetSecretsHmac()) > 0 {
		hc.SecretsHmac = base58.Encode(in.GetSecretsHmac())
	}
	if in.GetAttributes() != nil {
		attrs := &structpb.Struct{}
		if err := proto.Unmarshal(in.GetAttributes(), attrs); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to unmarshal attributes"))
		}
		hc.Attrs = &pb.HostCatalog_Attributes{
			Attributes: attrs,
		}
	}
	if in.Secrets != nil {
		hc.Secrets = in.Secrets
	}
	return hc, nil
}

// toPluginInfo converts a Plugin object into PluginInfo.
func toPluginInfo(plg *plg.Plugin) *plugins.PluginInfo {
	if plg == nil {
		return nil
	}
	return &plugins.PluginInfo{
		Id:          plg.GetPublicId(),
		Name:        plg.GetName(),
		Description: plg.GetDescription(),
	}
}

// toPluginPersistedData converts a *HostCatalogSecret from storage to a
// *plgpb.HostCatalogPersisted expected by a plugin. Project Id must be set.
func toPluginPersistedData(ctx context.Context, kmsCache *kms.Kms, projectId string, cSecret *HostCatalogSecret) (*plgpb.HostCatalogPersisted, error) {
	const op = "plugin.(Repository).getPersistedDataForCatalog"
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty project id")
	}
	if cSecret == nil {
		return nil, nil
	}
	dbWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get db wrapper"))
	}
	if err := cSecret.decrypt(ctx, dbWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	secrets := &structpb.Struct{}
	if err := proto.Unmarshal(cSecret.GetSecret(), secrets); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unmarshaling secret"))
	}
	return &plgpb.HostCatalogPersisted{Secrets: secrets}, nil
}
