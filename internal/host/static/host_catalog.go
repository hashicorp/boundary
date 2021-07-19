package static

import (
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A HostCatalog contains static hosts and static host sets. It is owned by
// a scope.
type HostCatalog struct {
	*store.HostCatalog
	tableName string `gorm:"-"`
}

// NewHostCatalog creates a new in memory HostCatalog assigned to scopeId.
// Name and description are the only valid options. All other options are
// ignored.
func NewHostCatalog(scopeId string, opt ...Option) (*HostCatalog, error) {
	if scopeId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, "static.NewHostCatalog", "no scope id")
	}

	opts := getOpts(opt...)
	hc := &HostCatalog{
		HostCatalog: &store.HostCatalog{
			ScopeId:     scopeId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	return hc, nil
}

func (c *HostCatalog) clone() *HostCatalog {
	cp := proto.Clone(c.HostCatalog)
	return &HostCatalog{
		HostCatalog: cp.(*store.HostCatalog),
	}
}

// TableName returns the table name for the host catalog.
func (c *HostCatalog) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "static_host_catalog"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (c *HostCatalog) SetTableName(n string) {
	c.tableName = n
}

func allocCatalog() *HostCatalog {
	fresh := &HostCatalog{
		HostCatalog: &store.HostCatalog{},
	}
	return fresh
}

func newCatalogMetadata(c *HostCatalog, op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.GetPublicId()},
		"resource-type":      []string{"static host catalog"},
		"op-type":            []string{op.String()},
	}
	if c.ScopeId != "" {
		metadata["scope-id"] = []string{c.ScopeId}
	}
	return metadata
}
