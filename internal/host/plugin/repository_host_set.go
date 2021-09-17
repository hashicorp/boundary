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
	"github.com/hashicorp/boundary/internal/oplog"
	hostplg "github.com/hashicorp/boundary/internal/plugin/host"
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

	c := allocHostCatalog()
	c.PublicId = s.GetCatalogId()
	if err := r.reader.LookupByPublicId(ctx, c); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get host catalog"))
	}

	// TODO: Contain the following plugin logic inside a plugin manager as well as
	//  calling the plugin which we have looked up.
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

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var preferredEndpoints []interface{}
	if s.PreferredEndpoints != nil {
		preferredEndpoints = make([]interface{}, 0, len(s.PreferredEndpoints))
		for i, e := range s.PreferredEndpoints {
			obj, err := host.NewPreferredEndpoint(ctx, s.PublicId, uint32(i+1), e)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
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
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in catalog: %s: name %s already exists", s.CatalogId, s.Name)))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in catalog: %s", s.CatalogId)))
	}
	return returnedHostSet, nil
}

// LookupSet will look up a host set in the repository and return the host
// set. If the host set is not found, it will return nil, nil.
// All options are ignored.
func (r *Repository) LookupSet(ctx context.Context, publicId string, opt ...host.Option) (*HostSet, error) {
	const op = "plugin.(Repository).LookupSet"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}

	sets, err := r.getSets(ctx, publicId, "", opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	switch {
	case len(sets) == 0:
		return nil, nil // not an error to return no rows for a "lookup"
	case len(sets) > 1:
		return nil, errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("%s matched more than 1 ", publicId))
	default:
		return sets[0], nil
	}
}

// ListSets returns a slice of HostSets for the catalogId. WithLimit is the
// only option supported.
func (r *Repository) ListSets(ctx context.Context, catalogId string, opt ...host.Option) ([]*HostSet, error) {
	const op = "plugin.(Repository).ListSets"
	if catalogId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing catalog id")
	}

	sets, err := r.getSets(ctx, "", catalogId, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return sets, nil
}

func (r *Repository) getSets(ctx context.Context, publicId string, catalogId string, opt ...host.Option) ([]*HostSet, error) {
	const op = "plugin.(Repository).getSets"
	const aggregateDelimiter = "|"
	const priorityDelimiter = "="

	if publicId == "" && catalogId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing search criteria: both host set id and catalog id are empty")
	}
	if publicId != "" && catalogId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "searching for both a host set id and a catalog id is not supported")
	}

	opts, err := host.GetOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
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
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in %s", publicId)))
	}

	if len(aggHostSets) == 0 {
		return nil, nil
	}

	sets := make([]*HostSet, 0, len(aggHostSets))
	for _, agg := range aggHostSets {
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
		sets = append(sets, hs)
	}

	return sets, nil
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

// TableName returns the table name for gorm
func (agg *hostSetAgg) TableName() string { return "host_plugin_host_set_with_value_obj" }
