// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/protobuf/proto"
)

// A Host is a temporarily cached plugin based resource.  The source of truth
// of the data contained here is provided by the service backing the plugin for
// this host.  The plugin for this host can be found by looking at the plugin
// field for this host's host catalog.
type Host struct {
	*store.Host
	PluginId  string   `gorm:"-"`
	SetIds    []string `gorm:"-"`
	tableName string   `gorm:"-"`
}

// NewHost creates a new in memory Host assigned to catalogId with an address.
// Supported options: WithName, WithDescription, WithIpAddresses, WithDnsNames,
// WithPluginId, WithPublicId. Others ignored.
func NewHost(ctx context.Context, catalogId, externalId string, opt ...Option) *Host {
	const op = "plugin.NewHost"
	opts := getOpts(opt...)

	// This check is the logical counterpart of the database constraints on the
	// external_name field. By replicating the checks as closely as possible in
	// code, we reduce the risk of SetSyncJob failing due to a bad external
	// name.
	if !strutil.Printable(opts.withExternalName) || len(opts.withExternalName) > 256 {
		event.WriteError(ctx, op,
			fmt.Errorf("ignoring host id %q external name %q due to its length (greater than 256 characters) or the presence of unsupported unicode characters",
				opts.withPublicId,
				opts.withExternalName),
		)
		opts.withExternalName = ""
	}

	h := &Host{
		PluginId: opts.withPluginId,
		Host: &store.Host{
			PublicId:     opts.withPublicId,
			CatalogId:    catalogId,
			ExternalId:   externalId,
			ExternalName: opts.withExternalName,
			Name:         opts.withName,
			Description:  opts.withDescription,
		},
	}
	if len(opts.withIpAddresses) > 0 {
		h.IpAddresses = make([]string, 0, len(opts.withIpAddresses))
		h.IpAddresses = append(h.IpAddresses, opts.withIpAddresses...)
	}
	if len(opts.withDnsNames) > 0 {
		h.DnsNames = make([]string, 0, len(opts.withDnsNames))
		h.DnsNames = append(h.DnsNames, opts.withDnsNames...)
	}

	return h
}

// For compatibility with the general Host type
func (h *Host) GetAddress() string {
	return ""
}

// TableName returns the table name for the host set.
func (h Host) TableName() string {
	if h.tableName != "" {
		return h.tableName
	}
	return "host_plugin_host"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (h *Host) SetTableName(n string) {
	h.tableName = n
}

// GetResourceType returns the resource type of the Host
func (h Host) GetResourceType() resource.Type {
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
		PluginId: h.PluginId,
		Host:     cp.(*store.Host),
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
		"resource-type":      []string{"plugin-host"},
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

// hostAgg is a view that aggregates the host's value objects in to
// string fields delimited with the aggregateDelimiter of "|"
type hostAgg struct {
	PublicId     string `gorm:"primary_key"`
	CatalogId    string
	ProjectId    string
	ExternalId   string
	ExternalName string
	PluginId     string
	Name         string
	Description  string
	CreateTime   *timestamp.Timestamp
	UpdateTime   *timestamp.Timestamp
	Version      uint32
	IpAddresses  string
	DnsNames     string
	SetIds       string
}

func (agg *hostAgg) toHost() *Host {
	const aggregateDelimiter = "|"
	h := allocHost()
	h.PublicId = agg.PublicId
	h.CatalogId = agg.CatalogId
	h.ExternalId = agg.ExternalId
	h.ExternalName = agg.ExternalName
	h.PluginId = agg.PluginId
	h.Name = agg.Name
	h.Description = agg.Description
	h.CreateTime = agg.CreateTime
	h.UpdateTime = agg.UpdateTime
	h.Version = agg.Version

	if agg.IpAddresses != "" {
		h.IpAddresses = strings.Split(agg.IpAddresses, aggregateDelimiter)
		sort.Strings(h.IpAddresses)
	}

	if agg.DnsNames != "" {
		h.DnsNames = strings.Split(agg.DnsNames, aggregateDelimiter)
		sort.Strings(h.DnsNames)
	}

	if agg.SetIds != "" {
		h.SetIds = strings.Split(agg.SetIds, aggregateDelimiter)
		sort.Strings(h.SetIds)
	}

	return h
}

// TableName returns the table name for gorm
func (agg *hostAgg) TableName() string {
	return "host_plugin_host_with_value_obj_and_set_memberships"
}

// GetPublicId returns the host public id as a string
func (agg *hostAgg) GetPublicId() string {
	return agg.PublicId
}

type deletedHost struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedHost) TableName() string {
	return "host_plugin_host_deleted"
}
