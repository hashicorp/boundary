package static

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static/store"
)

// A Host contains a static address.
type Host struct {
	*store.Host
	tableName string `gorm:"-"`
}

// NewHost creates a new in memory Host for address assigned to catalogId.
// Name and description are the only valid options. All other options are
// ignored.
func NewHost(catalogId string, opt ...Option) (*Host, error) {
	if catalogId == "" {
		return nil, fmt.Errorf("new: static host: no catalog id: %w", db.ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	host := &Host{
		Host: &store.Host{
			CatalogId: catalogId,
			Address:             opts.withAddress,
			Name:                opts.withName,
			Description:         opts.withDescription,
		},
	}
	return host, nil
}

// TableName returns the table name for the host.
func (h *Host) TableName() string {
	if h.tableName != "" {
		return h.tableName
	}
	return "static_host"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (h *Host) SetTableName(n string) {
	h.tableName = n
}
