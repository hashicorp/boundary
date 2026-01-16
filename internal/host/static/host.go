// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"sort"
	"strings"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

const (
	MinHostAddressLength = 3
	MaxHostAddressLength = 255
)

// A Host contains a static address.
type Host struct {
	*store.Host
	SetIds    []string `gorm:"-"`
	tableName string   `gorm:"-"`
}

// NewHost creates a new in memory Host for address assigned to catalogId.
// Name and description are the only valid options. All other options are
// ignored.
func NewHost(ctx context.Context, catalogId string, opt ...Option) (*Host, error) {
	const op = "static.NewHost"
	if catalogId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
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

// For compatibility with the general Host type
func (h *Host) GetIpAddresses() []string {
	return nil
}

// For compatibility with the general Host type
func (h *Host) GetDnsNames() []string {
	return nil
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

// GetResourceType returns the resource type of the Host
func (h *Host) GetResourceType() resource.Type {
	return resource.Host
}

func allocHost() *Host {
	return &Host{
		Host: &store.Host{},
	}
}

func (h *Host) clone() *Host {
	cp := proto.Clone(h.Host)
	nh := &Host{
		Host: cp.(*store.Host),
	}
	switch {
	case h.SetIds == nil:
	case len(h.SetIds) == 0:
		nh.SetIds = make([]string, 0)
	default:
		nh.SetIds = make([]string, len(h.SetIds))
		copy(nh.SetIds, h.SetIds)
	}
	return nh
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

// GetSetIds returns host set ids
func (h *Host) GetSetIds() []string {
	return h.SetIds
}

type hostAgg struct {
	PublicId    string `gorm:"primary_key"`
	CatalogId   string
	Name        string
	Description string
	CreateTime  *timestamp.Timestamp
	UpdateTime  *timestamp.Timestamp
	Version     uint32
	Address     string
	SetIds      string
}

func (agg *hostAgg) toHost() *Host {
	h := allocHost()
	h.PublicId = agg.PublicId
	h.CatalogId = agg.CatalogId
	h.Name = agg.Name
	h.Description = agg.Description
	h.CreateTime = agg.CreateTime
	h.UpdateTime = agg.UpdateTime
	h.Version = agg.Version
	h.Address = agg.Address
	h.SetIds = agg.getSetIds()
	return h
}

// TableName returns the table name for gorm
func (agg *hostAgg) TableName() string {
	return "static_host_with_set_memberships"
}

// GetPublicId returns the host public id as a string
func (agg *hostAgg) GetPublicId() string {
	return agg.PublicId
}

// GetSetIds returns a list of all associated host sets to the host
func (agg *hostAgg) getSetIds() []string {
	const aggregateDelimiter = "|"
	var ids []string
	if agg.SetIds != "" {
		ids = strings.Split(agg.SetIds, aggregateDelimiter)
		sort.Strings(ids)
	}
	return ids
}

type deletedHost struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedHost) TableName() string {
	return "static_host_deleted"
}
