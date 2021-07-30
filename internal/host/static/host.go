package static

import (
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

const (
	MinHostAddressLength = 3
	MaxHostAddressLength = 255
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
		return nil, errors.NewDeprecated(errors.InvalidParameter, "static.NewHost", "no catalog id")
	}

	opts := getOpts(opt...)
	host := &Host{
		Host: &store.Host{
			CatalogId:   catalogId,
			Address:     opts.withAddress,
			Name:        opts.withName,
			Description: opts.withDescription,
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

func allocHost() *Host {
	return &Host{
		Host: &store.Host{},
	}
}

func (h *Host) clone() *Host {
	cp := proto.Clone(h.Host)
	return &Host{
		Host: cp.(*store.Host),
	}
}

func (h *Host) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{h.PublicId},
		"resource-type":      []string{"static-host"},
		"op-type":            []string{op.String()},
	}
	if h.CatalogId != "" {
		metadata["catalog-id"] = []string{h.CatalogId}
	}
	return metadata
}
