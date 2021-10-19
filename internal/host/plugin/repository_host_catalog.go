package plugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
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
				q, v := newSecret.insertQuery()
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

// DeleteCatalog deletes id from the repository returning a count of the
// number of records deleted.
func (r *Repository) DeleteCatalog(ctx context.Context, id string, _ ...Option) (int, error) {
	const op = "plugin.(Repository).DeleteCatalog"
	if id == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}

	c := allocHostCatalog()
	c.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, c); err != nil {
		if errors.IsNotFoundError(err) {
			return db.NoRowsAffected, nil
		}
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", id)))
	}
	if c.ScopeId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	plgClient, ok := r.plugins[c.GetPluginId()]
	if !ok || plgClient == nil {
		return 0, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("plugin %q not available", c.GetPluginId()))
	}
	plgHc, err := toPluginCatalog(ctx, c)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	// TODO: include all the sets for this catalog in the delete catalog request.
	_, err = plgClient.OnDeleteCatalog(ctx, &plgpb.OnDeleteCatalogRequest{Catalog: plgHc})
	if err != nil {
		// Even if the plugin returns an error, we ignore it and proceed
		// with deleting the catalog.
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
// present.  c must have a valid Public Id and Scope Id set.
// TODO: consider merging the functions for getting catalog and persisted data into a view.
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
		Id:      in.GetPublicId(),
		ScopeId: in.GetScopeId(),
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
