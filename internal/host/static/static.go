package static

import (
	"errors"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/host/static/store"
)

// A HostCatalog contains static hosts and static host sets.
type HostCatalog struct {
	*store.HostCatalog
	tableName string `gorm:"-"`
}

// NewHostCatalog creates a new in memory HostCatalog assigned to scopeId.
// Name and description are the only valid options. All other options are
// ignored.
func NewHostCatalog(scopeId string, opt ...Option) (*HostCatalog, error) {
	if scopeId == "" {
		return nil, errors.New("empty scopeId")
	}
	id, err := db.NewPublicId("sthc")
	if err != nil {
		return nil, err
	}
	opts := getOpts(opt...)
	hc := &HostCatalog{
		HostCatalog: &store.HostCatalog{
			ScopeId:     scopeId,
			Name:        opts.withName,
			Description: opts.withDescription,
			PublicId:    id,
		},
	}
	return hc, nil
}

// TableName returns the table name for the host catalog.
func (c *HostCatalog) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "static_host_catalog"
}

// SetTableName sets the table name.
func (c *HostCatalog) SetTableName(n string) {
	if n != "" {
		c.tableName = n
	}
}

type Host struct {
	*store.Host
	tableName string `gorm:"-"`
}

func NewHost(opt ...Option) *Host {
	return nil
}
