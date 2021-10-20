package host

import (
	"github.com/hashicorp/boundary/internal/host/store"
	"github.com/hashicorp/boundary/internal/oplog"
)

// A SetWrapper wraps a *store.Set so we can provide a tableName to gorm and get
// oplog metadata. We don't use *Set because Set is already defined as a common
// interface.
type SetWrapper struct {
	*store.Set
	tableName string `gorm:"-"`
}

// TableName returns the table name for the host set.
func (m *SetWrapper) TableName() string {
	if m.tableName != "" {
		return m.tableName
	}
	return "host_set"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (m *SetWrapper) SetTableName(n string) {
	m.tableName = n
}

func (s *SetWrapper) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{s.PublicId},
		"resource-type":      []string{"host-set"},
		"op-type":            []string{op.String()},
	}
	if s.CatalogId != "" {
		metadata["catalog-id"] = []string{s.CatalogId}
	}
	return metadata
}
