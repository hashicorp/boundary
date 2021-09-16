package plugin

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	hostplg "github.com/hashicorp/boundary/internal/plugin/host"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
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
func (r *Repository) CreateCatalog(ctx context.Context, c *HostCatalog, _ ...Option) (*HostCatalog, error) {
	const op = "plugin.(Repository).CreateCatalog"
	if c == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil HostCatalog")
	}
	if c.HostCatalog == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil embedded HostCatalog")
	}
	if c.ScopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	if c.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	if c.PluginId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no plugin id")
	}
	if c.Attributes == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil attributes")
	}
	c = c.clone()

	plg := hostplg.NewPlugin("", "")
	plg.PublicId = c.PluginId
	if err := r.reader.LookupByPublicId(ctx, plg); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter), errors.WithMsg(fmt.Sprintf("can't find plugin with id: %q", c.GetPluginId())))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get host plugin with id %q", c.PluginId)))
	}

	id, err := newHostCatalogId(ctx, plg.GetIdPrefix())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	c.PublicId = id

	plgClient, ok := r.plugins[plg.GetPublicId()]
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("expected plugin %q not available", plg.GetPluginName()))
	}
	plgHc, err := toPluginCatalog(ctx, c)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	plgResp, err := plgClient.OnCreateCatalog(ctx, &plgpb.OnCreateCatalogRequest{Catalog: plgHc})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	persistedData := plgResp.GetPersisted().GetData()

	var hcSecret *HostCatalogSecret
	if persistedData != nil {
		hcSecret, err = newHostCatalogSecret(ctx, id, persistedData.AsMap())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		dbWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get db wrapper"))
		}
		if err := hcSecret.encrypt(ctx, dbWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
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
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in scope: %s: name %s already exists", c.ScopeId, c.Name)))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in scope: %s", c.ScopeId)))
	}
	return newHostCatalog, nil
}

// LookupCatalog returns the HostCatalog for id. Returns nil, nil if no
// HostCatalog is found for id.
func (r *Repository) LookupCatalog(ctx context.Context, id string, _ ...Option) (*HostCatalog, error) {
	const op = "plugin.(Repository).LookupCatalog"
	if id == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	c := allocHostCatalog()
	c.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, c); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", id)))
	}
	return c, nil
}

// ListCatalogs returns a slice of HostCatalogs for the scope IDs. WithLimit is the only option supported.
func (r *Repository) ListCatalogs(ctx context.Context, scopeIds []string, opt ...Option) ([]*HostCatalog, error) {
	const op = "plugin.(Repository).ListCatalogs"
	if len(scopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var hostCatalogs []*HostCatalog
	err := r.reader.SearchWhere(ctx, &hostCatalogs, "scope_id in (?)", []interface{}{scopeIds}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return hostCatalogs, nil
}

// toPluginCatalog returns a host catalog, with it's secret if available, in the format expected
// by the host plugin system.
func toPluginCatalog(ctx context.Context, in *HostCatalog) (*pb.HostCatalog, error) {
	const op = "plugin.toPluginCatalog"
	if in == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil storage plugin")
	}
	hc := &pb.HostCatalog{
		Id:                          in.GetPublicId(),
		ScopeId:                     in.GetScopeId(),
	}
	if in.GetAttributes() != nil {
		attrs := map[string]interface{}{}
		if err := json.Unmarshal(in.GetAttributes(), &attrs); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to unmarshal attributes"))
		}
		if len(attrs) > 0 {
			attrSt, err := structpb.NewStruct(attrs)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to proto marshal attributes"))
			}
			hc.Attributes = attrSt
		}
	}
	if in.secrets != nil {
		secrets := map[string]interface{}{}
		if err := json.Unmarshal(in.secrets, &secrets); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to json unmarshal secrets"))
		}
		if len(secrets) > 0 {
			secretSt, err := structpb.NewStruct(secrets)
			if err != nil {
				// Create a new error instead of wrapping it in case the error contains some secret info.
				return nil, errors.New(ctx, errors.Internal, op, "unable to proto marshal secrets")
			}
			hc.Secrets = secretSt
		}
	}
	return hc, nil
}