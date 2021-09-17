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
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/protobuf/types/known/structpb"
)

// CreateSet inserts s into the repository and returns a new HostSet
// containing the host set's PublicId. s is not changed. s must contain a
// valid CatalogId. s must not contain a PublicId. The PublicId is
// generated and assigned by this method. opt is ignored.
//
// Both s.Name and s.Description are optional. If s.Name is set, it must be
// unique within s.CatalogId.
func (r *Repository) CreateSet(ctx context.Context, scopeId string, s *HostSet, _ ...Option) (*HostSet, error) {
	const op = "plugin.(Repository).CreateSet"
	if s == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil HostSet")
	}
	if s.HostSet == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil embedded HostSet")
	}
	if s.CatalogId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	}
	if s.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	if s.Attributes == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil attributes")
	}
	s = s.clone()

	c, err := r.getCatalog(ctx, s.CatalogId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("looking up catalog"))
	}
	per, err := r.getPersistedDataForCatalog(ctx, c)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("looking up persisted data"))
	}

	plg := hostplg.NewPlugin("", "")
	plg.PublicId = c.GetPluginId()
	if err := r.reader.LookupByPublicId(ctx, plg); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get host plugin"))
	}

	id, err := newHostSetId(ctx, plg.GetIdPrefix())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	s.PublicId = id

	plgClient, ok := r.plugins[plg.GetPublicId()]
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("plugin with plugin name %q not available", plg.GetPluginName()))
	}
	plgHc, err := toPluginCatalog(ctx, c)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	plgHs, err := toPluginSet(ctx, s)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if _, err := plgClient.OnCreateSet(ctx, &plgpb.OnCreateSetRequest{Catalog: plgHc, Set: plgHs, Persisted: per}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var newHostSet *HostSet
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newHostSet = s.clone()
			err := w.Create(ctx, newHostSet, db.WithOplog(oplogWrapper, s.oplog(oplog.OpType_OP_TYPE_CREATE)))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in catalog: %s: name %s already exists", s.CatalogId, s.Name)))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in catalog: %s", s.CatalogId)))
	}
	return newHostSet, nil
}

// LookupSet will look up a host set in the repository and return the host
// set. If the host set is not found, it will return nil, nil.
// All options are ignored.
func (r *Repository) LookupSet(ctx context.Context, publicId string, _ ...Option) (*HostSet, error) {
	const op = "plugin.(Repository).LookupSet"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}

	s := allocHostSet()
	s.PublicId = publicId

	err := r.reader.LookupByPublicId(ctx, s)
	if errors.IsNotFoundError(err) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s", s.PublicId)))
	}

	return s, nil
}

// ListSets returns a slice of HostSets for the catalogId. WithLimit is the
// only option supported.
func (r *Repository) ListSets(ctx context.Context, catalogId string, opt ...Option) ([]*HostSet, error) {
	const op = "plugin.(Repository).ListSets"
	if catalogId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var sets []*HostSet
	err := r.reader.SearchWhere(ctx, &sets, "catalog_id = ?", []interface{}{catalogId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return sets, nil
}

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
		attrs := map[string]interface{}{}
		if err := json.Unmarshal(in.GetAttributes(), &attrs); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to marshal attributes"))
		}
		if len(attrs) > 0 {
			attrSt, err := structpb.NewStruct(attrs)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("proto marshaling attributes"))
			}
			hs.Attributes = attrSt
		}
	}
	return hs, nil
}
