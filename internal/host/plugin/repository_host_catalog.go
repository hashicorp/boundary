package plugin

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	hostPlugin "github.com/hashicorp/boundary/internal/plugin/host"
	hostSdkProto "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	hostPluginProto "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// CreateCatalog inserts c into the repository and returns a new
// HostCatalog containing the catalog's PublicId. c must contain a valid
// ScopeID and PluginID. c must not contain a PublicId. The PublicId is
// generated and assigned by this method. The plugin manager must
// also be present. opt is ignored.
//
// c.Secret, c.Name and c.Description are optional. If c.Name is set, it must be
// unique within c.ScopeID.  If c.Secret is set, it will be stored encrypted but
// not included in the returned *HostCatalog.
//
// Both c.CreateTime and c.UpdateTime are ignored.
func (r *Repository) CreateCatalog(ctx context.Context, c *HostCatalog, m *hostPlugin.PluginManager, _ ...Option) (*HostCatalog, error) {
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
	if m == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing plugin manager")
	}
	c = c.clone()

	// Validate the name before we run OnCreateCatalog. This should be
	// done for other DB-related constraints too, as running
	// OnCreateCatalog will possibly cause cloud-side changes that may
	// need to be cleaned up in the event of error.
	existingC, err := r.LookupCatalogByNameAndScope(ctx, c.Name, c.ScopeId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if existingC != nil && c.ScopeId == existingC.ScopeId {
		return nil, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("duplicate catalog name %q in scope %q", c.Name, c.ScopeId))
	}

	// Run plugin's OnCreateCatalog function
	pluginClient, pluginIdPrefix, err := m.LoadPlugin(ctx, c.PluginId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	id, err := newHostCatalogId(ctx, pluginIdPrefix)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	c.PublicId = id

	catProto, err := toProto(c)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	resp, err := pluginClient.OnCreateCatalog(ctx, &hostPluginProto.OnCreateCatalogRequest{
		Catalog: catProto,
	})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	dbWrapper, err := r.kms.GetWrapper(ctx, c.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get db wrapper"))
	}

	var hcSecret *HostCatalogSecret
	if resp.GetPersisted().GetData() != nil {
		// Persisted data has been returned, encrypt the data for
		// storage.
		hcSecret, err = newHostCatalogSecret(ctx, id, resp.GetPersisted().GetData().AsMap())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		hcSecret.encrypt(ctx, dbWrapper)
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

// LookupCatalogByNameAndScope returns the HostCatalog for name and
// scope ID. The name can be empty, but the scope ID must not.
func (r *Repository) LookupCatalogByNameAndScope(ctx context.Context, name, scopeId string, _ ...Option) (*HostCatalog, error) {
	const op = "plugin.(Repository).LookupCatalogByNameAndScope"
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "name is empty")
	}

	if name != "" {
		return r.lookupCatalogByNameAndScope_withName(ctx, name, scopeId)
	}

	return r.lookupCatalogByNameAndScope_blankName(ctx, scopeId)
}

func (r *Repository) lookupCatalogByNameAndScope_withName(ctx context.Context, name, scopeId string, _ ...Option) (*HostCatalog, error) {
	const op = "plugin.(Repository).LookupCatalogByNameAndScope_withName"
	c := allocHostCatalog()
	if err := r.reader.LookupWhere(ctx, c, "name = ? and scope_id = ?", name, scopeId); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", name)))
	}
	return c, nil
}

func (r *Repository) lookupCatalogByNameAndScope_blankName(ctx context.Context, scopeId string, _ ...Option) (*HostCatalog, error) {
	const op = "plugin.(Repository).LookupCatalogByNameAndScope_blankName"

	// To look up on blank names reliably, we just simply search on scope ID,
	// iterate through, and return the one with a blank name. Return nil, nil if
	// we don't have a match.
	cats, err := r.ListCatalogs(ctx, []string{scopeId})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	for _, cat := range cats {
		if cat.GetName() == "" {
			return cat, nil
		}
	}

	return nil, nil
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

// toProto converts from the internal HostCatalog protobuf message to
// the external API format expected by plugin calls.
func toProto(in *HostCatalog) (*hostSdkProto.HostCatalog, error) {
	var attrsRaw map[string]interface{}
	if err := json.Unmarshal(in.GetAttributes(), &attrsRaw); err != nil {
		return nil, fmt.Errorf("cannot convert attributes: %w", err)
	}
	attrs, err := structpb.NewStruct(attrsRaw)
	if err != nil {
		return nil, fmt.Errorf("cannot convert attributes: %w", err)
	}

	secrets, err := structpb.NewStruct(in.secrets)
	if err != nil {
		// Don't wrap structpb error here to avoid leaking secret data
		return nil, fmt.Errorf("cannot convert secrets: malformed data")
	}

	return &hostSdkProto.HostCatalog{
		Id:          in.GetPublicId(),
		ScopeId:     in.GetScopeId(),
		Type:        Subtype.String(),
		Attributes:  attrs,
		Secrets:     secrets,
		Description: wrapperspb.String(in.GetDescription()),
		Name:        wrapperspb.String(in.GetName()),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
		Version:     in.GetVersion(),
	}, nil
}
