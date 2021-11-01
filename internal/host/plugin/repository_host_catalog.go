package plugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/patchstruct"
	"github.com/hashicorp/boundary/internal/oplog"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// CreateCatalog inserts c into the repository and returns a new
// HostCatalog containing the catalog's PublicId. c must contain a valid
// ScopeID and PluginID. c must not contain a PublicId. The PublicId is
// generated and assigned by this method. opt is ignored.
//
// c.Secret, c.Name and c.Description are optional. If c.Name is set, it must be
// unique within c.ScopeID.  If c.Secret is set, it will be stored encrypted but
// not included in the returned *HostCatalog.
//
// Both c.CreateTime and c.UpdateTime are ignored.
func (r *Repository) CreateCatalog(ctx context.Context, c *HostCatalog, _ ...Option) (*HostCatalog, *hostplugin.Plugin, error) {
	const op = "plugin.(Repository).CreateCatalog"
	if c == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "nil HostCatalog")
	}
	if c.HostCatalog == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "nil embedded HostCatalog")
	}
	if c.ScopeId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
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

	plgClient, ok := r.plugins[c.GetPluginId()]
	if !ok || plgClient == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("plugin %q not available", c.GetPluginId()))
	}
	plgHc, err := toPluginCatalog(ctx, c)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	plgResp, err := plgClient.OnCreateCatalog(ctx, &plgpb.OnCreateCatalogRequest{Catalog: plgHc})
	if err != nil {
		if status.Code(err) != codes.Unimplemented {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
	}

	var hcSecret *HostCatalogSecret
	if plgResp != nil && plgResp.GetPersisted().GetSecrets() != nil {
		hcSecret, err = newHostCatalogSecret(ctx, id, plgResp.GetPersisted().GetSecrets())
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		dbWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get db wrapper"))
		}
		if err := hcSecret.encrypt(ctx, dbWrapper); err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var newHostCatalog *HostCatalog
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 3)
			ticket, err := w.GetTicket(c)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			newHostCatalog = c.clone()
			var cOplogMsg oplog.Message
			if err := w.Create(ctx, newHostCatalog, db.NewOplogMsg(&cOplogMsg)); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			msgs = append(msgs, &cOplogMsg)

			if hcSecret != nil {
				newSecret := hcSecret.clone()
				q, v := newSecret.upsertQuery()
				rows, err := w.Exec(ctx, q, v)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if rows > 1 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 catalog secret would have been created")
				}
				msgs = append(msgs, newSecret.oplogMessage(db.CreateOp))
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
			return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in scope: %s: name %s already exists", c.ScopeId, c.Name)))
		}
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in scope: %s", c.ScopeId)))
	}
	plg, err := r.getPlugin(ctx, newHostCatalog.GetPluginId())
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
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
//
// The first integer value represents the number of catalogs updated.
// The second represents the number of secrets updated. There should
// always be one catalog updated if there is no error. It's possible
// that zero rows may be affected for secrets, but this will be rare,
// as this operation is opaque and the update is only skipped if
// there are no secrets returned altogether.
func (r *Repository) UpdateCatalog(ctx context.Context, c *HostCatalog, version uint32, fieldMask []string, _ ...Option) (*HostCatalog, int, int, error) {
	const op = "plugin.(Repository).UpdateCatalog"
	if c == nil {
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil HostCatalog")
	}
	if c.HostCatalog == nil {
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil embedded HostCatalog")
	}
	if c.PublicId == "" {
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	if c.ScopeId == "" {
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	if len(fieldMask) == 0 {
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "empty field mask")
	}

	// Quickly replace the passed in HostCatalog with a clone. This
	// ensures that we don't alter anything in the original passed in
	// parameters, which we don't do by convention. We will be adding
	// to this "working set" as we move through the method.
	c = c.clone()

	// Get the old catalog first. We patch the record first before
	// sending it to the DB for updating so that we can run on
	// OnUpdateCatalog. Note that the field masks are still used for
	// updating.
	currentCatalog, _, err := r.LookupCatalog(ctx, c.PublicId)
	if err != nil {
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error looking up catalog with id %q", c.PublicId)))
	}

	if currentCatalog == nil {
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("catalog with id %q not found", c.PublicId))
	}

	// Clone the catalog so that we can set fields.
	newCatalog := currentCatalog.clone()
	var dbMask, nullFields []string
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
		case strings.EqualFold("attributes", f) && c.Attributes != nil:
			// Attributes are patched from the JSON included in the mask to
			// the attributes that exist in the record.
			dbMask = append(dbMask, "attributes")
			newCatalog.Attributes, err = patchstruct.PatchBytes(newCatalog.Attributes, c.Attributes)
			if err != nil {
				return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("error in catalog attribute JSON"))
			}

			// Patch the working set with the new attributes.
			c.Attributes = newCatalog.Attributes
		case strings.EqualFold("secrets", f):
			// While in a similar format, secrets are passed along
			// wholesale (for the time being). Don't append this mask
			// field, as secrets do not have a database entry. Clear the
			// secrets out of the working set after.
			newCatalog.Secrets = c.Secrets
			c.Secrets = nil

		default:
			return nil, db.NoRowsAffected, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}

	// Get the plugin client.
	plgClient, ok := r.plugins[currentCatalog.GetPluginId()]
	if !ok || plgClient == nil {
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("plugin %q not available", currentCatalog.GetPluginId()))
	}

	// Convert the catalog values to API protobuf values, which is what
	// we use for the plugin hook calls.
	currPlgHc, err := toPluginCatalog(ctx, currentCatalog)
	if err != nil {
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	newPlgHc, err := toPluginCatalog(ctx, newCatalog)
	if err != nil {
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	// Get the secrets for the host catalog.
	currentCatalogPersisted, err := r.getPersistedDataForCatalog(ctx, currentCatalog)
	if err != nil {
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error looking up persisted data for catalog with id %q", c.PublicId)))
	}

	plgResp, err := plgClient.OnUpdateCatalog(ctx, &plgpb.OnUpdateCatalogRequest{
		CurrentCatalog: currPlgHc,
		NewCatalog:     newPlgHc,
		Persisted:      currentCatalogPersisted,
	})
	if err != nil {
		if status.Code(err) != codes.Unimplemented {
			return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
	}

	// Success for OnUpdateCatalog. This means we can start updating.
	// First, check for returned persisted data and encrypt it.
	var hcSecret *HostCatalogSecret
	var deleteSecrets bool
	if plgResp != nil && plgResp.GetPersisted().GetSecrets() != nil {
		if len(plgResp.GetPersisted().GetSecrets().GetFields()) == 0 {
			// Flag the secret to be deleted.
			hcSecret, err = newHostCatalogSecret(ctx, currentCatalog.GetPublicId(), plgResp.GetPersisted().GetSecrets())
			if err != nil {
				return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}

			deleteSecrets = true
		} else {
			hcSecret, err = newHostCatalogSecret(ctx, currentCatalog.GetPublicId(), plgResp.GetPersisted().GetSecrets())
			if err != nil {
				return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}
			dbWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeDatabase)
			if err != nil {
				return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get db wrapper"))
			}
			if err := hcSecret.encrypt(ctx, dbWrapper); err != nil {
				return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op)
			}
		}
	}

	// Get the oplog.
	oplogWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var catalogsUpdated, secretsUpdated int
	var returnedCatalog *HostCatalog
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 3)
			ticket, err := w.GetTicket(c)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			if len(dbMask) != 0 || len(nullFields) != 0 {
				returnedCatalog = c.clone()
				var cOplogMsg oplog.Message
				catalogsUpdated, err = w.Update(
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
				if catalogsUpdated > 1 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
				}
				msgs = append(msgs, &cOplogMsg)
			} else {
				// Returned catalog needs to be the old copy, as no fields in the
				// catalog itself are being updated (note: secrets may still be
				// updated).
				returnedCatalog = currentCatalog.clone()
			}

			if hcSecret != nil {
				if deleteSecrets {
					// We didn't set/encrypt the persisted data because there was
					// none returned. Just delete the entry.
					deletedSecret := hcSecret.clone()
					q, v := deletedSecret.deleteQuery()
					var err error
					secretsUpdated, err = w.Exec(ctx, q, v)
					if err != nil {
						return errors.Wrap(ctx, err, op)
					}
					if secretsUpdated != 1 {
						return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("expected 1 catalog secret to be deleted, got %d", secretsUpdated))
					}
					msgs = append(msgs, deletedSecret.oplogMessage(db.DeleteOp))
				} else {
					// Update the secrets.
					updatedSecret := hcSecret.clone()
					q, v := updatedSecret.upsertQuery()
					var err error
					secretsUpdated, err = w.Exec(ctx, q, v)
					if err != nil {
						return errors.Wrap(ctx, err, op)
					}
					if secretsUpdated > 1 {
						return errors.New(ctx, errors.MultipleRecords, op, "more than 1 catalog secret would have been updated")
					}
					msgs = append(msgs, updatedSecret.oplogMessage(db.UpdateOp))
				}
			}

			metadata := c.oplog(oplog.OpType_OP_TYPE_UPDATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s: name %s already exists", c.PublicId, c.Name)))
		}
		return nil, db.NoRowsAffected, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s", c.PublicId)))
	}

	return returnedCatalog, catalogsUpdated, secretsUpdated, nil
}

// LookupCatalog returns the HostCatalog for id. Returns nil, nil if no
// HostCatalog is found for id.
func (r *Repository) LookupCatalog(ctx context.Context, id string, _ ...Option) (*HostCatalog, *hostplugin.Plugin, error) {
	const op = "plugin.(Repository).LookupCatalog"
	if id == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	c, err := r.getCatalog(ctx, id)
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

// ListCatalogs returns a slice of HostCatalogs for the scope IDs. WithLimit is the only option supported.
func (r *Repository) ListCatalogs(ctx context.Context, scopeIds []string, opt ...host.Option) ([]*HostCatalog, []*hostplugin.Plugin, error) {
	const op = "plugin.(Repository).ListCatalogs"
	if len(scopeIds) == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
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
	var hostCatalogs []*HostCatalog
	if err := r.reader.SearchWhere(ctx, &hostCatalogs, "scope_id in (?)", []interface{}{scopeIds}, db.WithLimit(limit)); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	plgIds := make([]string, 0, len(hostCatalogs))
	for _, c := range hostCatalogs {
		plgIds = append(plgIds, c.PluginId)
	}
	var plgs []*hostplugin.Plugin
	if err := r.reader.SearchWhere(ctx, &plgs, "public_id in (?)", []interface{}{plgIds}); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return hostCatalogs, plgs, nil
}

// DeleteCatalog deletes catalog for the provided id from the repository
// returning a count of the number of records deleted. All options are ignored.
func (r *Repository) DeleteCatalog(ctx context.Context, id string, _ ...Option) (int, error) {
	const op = "plugin.(Repository).DeleteCatalog"
	if id == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}

	c, err := r.getCatalog(ctx, id)
	if err != nil && !errors.IsNotFoundError(err) {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	if c == nil {
		return db.NoRowsAffected, nil
	}
	p, err := r.getPersistedDataForCatalog(ctx, c)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	plgClient, ok := r.plugins[c.GetPluginId()]
	if !ok || plgClient == nil {
		return 0, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("plugin %q not available", c.GetPluginId()))
	}
	plgHc, err := toPluginCatalog(ctx, c)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	// TODO: Include all the sets for this catalog in the delete catalog request.  We don't need it for now
	//   since our currently provided plugins only read data for set configuration, but in the future that might
	//   change.
	_, err = plgClient.OnDeleteCatalog(ctx, &plgpb.OnDeleteCatalogRequest{Catalog: plgHc, Persisted: p})
	if err != nil {
		// Even if the plugin returns an error, we ignore it and proceed with
		// deleting the catalog.
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeOplog)
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
func (r *Repository) getCatalog(ctx context.Context, id string) (*HostCatalog, error) {
	const op = "plugin.(Repository).getCatalog"
	c := allocHostCatalog()
	c.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, c); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", id)))
	}
	return c, nil
}

// getPersistedDataForCatalog returns the persisted data for a catalog if
// present. c must have a valid Public Id and Scope Id set.  TODO: consider
// merging the functions for getting catalog and persisted data into a view.
func (r *Repository) getPersistedDataForCatalog(ctx context.Context, c *HostCatalog) (*plgpb.HostCatalogPersisted, error) {
	const op = "plugin.(Repository).getPersistedDataForCatalog"
	if c.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty public id")
	}
	if c.ScopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty scope id")
	}
	cSecret := allocHostCatalogSecret()
	if err := r.reader.LookupWhere(ctx, cSecret, "catalog_id=?", c.GetPublicId()); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	if cSecret == nil {
		return nil, nil
	}
	dbWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeDatabase)
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

func (r *Repository) getPlugin(ctx context.Context, plgId string) (*hostplugin.Plugin, error) {
	const op = "plugin.(Repository).getPlugin"
	if plgId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no plugin id")
	}
	plg := hostplugin.NewPlugin()
	plg.PublicId = plgId
	if err := r.reader.LookupByPublicId(ctx, plg); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get host plugin with id %q", plgId)))
	}
	return plg, nil
}

// toPluginCatalog returns a host catalog, with it's secret if available, in the format expected
// by the host plugin system.
func toPluginCatalog(ctx context.Context, in *HostCatalog) (*pb.HostCatalog, error) {
	const op = "plugin.toPluginCatalog"
	if in == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil storage plugin")
	}
	hc := &pb.HostCatalog{
		Id:          in.GetPublicId(),
		ScopeId:     in.GetScopeId(),
		Name:        wrapperspb.String(in.GetName()),
		Description: wrapperspb.String(in.GetDescription()),
	}
	if in.GetAttributes() != nil {
		attrs := &structpb.Struct{}
		if err := proto.Unmarshal(in.GetAttributes(), attrs); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to unmarshal attributes"))
		}
		hc.Attributes = attrs
	}
	if in.Secrets != nil {
		hc.Secrets = in.Secrets
	}
	return hc, nil
}
