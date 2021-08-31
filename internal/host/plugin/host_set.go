package plugin

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A HostSet is a collection of hosts from the set's catalog.
type HostSet struct {
	*store.HostSet
	tableName string `gorm:"-"`
}

// NewHostSet creates a new in memory HostSet assigned to catalogId.
// Attributes, name, and description are the only valid options. All other
// options are ignored.
func NewHostSet(ctx context.Context, catalogId string, opt ...Option) (*HostSet, error) {
	const op = "plugin.NewHostSet"
	opts := getOpts(opt...)
	set := &HostSet{
		HostSet: &store.HostSet{
			CatalogId:   catalogId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}

	if opts.withAttributes != nil {
		attrs, err := json.Marshal(opts.withAttributes)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
		}
		set.Attributes = attrs
	}
	return set, nil
}

// TableName returns the table name for the host set.
func (s *HostSet) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return "plugin_host_set"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (s *HostSet) SetTableName(n string) {
	s.tableName = n
}

func allocHostSet() *HostSet {
	return &HostSet{
		HostSet: &store.HostSet{},
	}
}

func (s *HostSet) clone() *HostSet {
	cp := proto.Clone(s.HostSet)
	return &HostSet{
		HostSet: cp.(*store.HostSet),
	}
}

func (s *HostSet) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{s.PublicId},
		"resource-type":      []string{"plugin-host-set"},
		"op-type":            []string{op.String()},
	}
	if s.CatalogId != "" {
		metadata["catalog-id"] = []string{s.CatalogId}
	}
	return metadata
}
