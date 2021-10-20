package plugin

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"google.golang.org/protobuf/proto"
)

// A Host is a temporarily cached plugin based resource.  The source of truth
// of the data contained here is provided by the service backing the plugin for
// this host.  The plugin for this host can be found by looking at the plugin
// field for this host's host catalog.
type Host struct {
	*store.Host
	PluginId  string `gorm:"-"`
	tableName string `gorm:"-"`
}

// newHost creates a new in memory Host assigned to catalogId with an address.
// Supported options: WithName, WithDescription, WithIpAddresses, WithDnsNames,
// WithPluginId. Others ignored.
func newHost(ctx context.Context, catalogId, externalId string, opt ...Option) *Host {
	opts := getOpts(opt...)

	h := &Host{
		PluginId: opts.withPluginId,
		Host: &store.Host{
			CatalogId:   catalogId,
			ExternalId:  externalId,
			Name:        opts.withName,
			Description: opts.withDescription,
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
func (s *Host) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return "host_plugin_host"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (s *Host) SetTableName(n string) {
	s.tableName = n
}

func allocHost() *Host {
	return &Host{
		Host: &store.Host{},
	}
}

func (h *Host) clone() *Host {
	cp := proto.Clone(h.Host)
	return &Host{
		PluginId: h.PluginId,
		Host:     cp.(*store.Host),
	}
}

// hostAgg is a view that aggregates the host's value objects in to
// string fields delimited with the aggregateDelimiter of "|"
type hostAgg struct {
	PublicId    string `gorm:"primary_key"`
	CatalogId   string
	ExternalId  string
	PluginId    string
	Name        string
	Description string
	CreateTime  *timestamp.Timestamp
	UpdateTime  *timestamp.Timestamp
	IpAddresses string
	DnsNames    string
}

func (agg *hostAgg) toHost(ctx context.Context) (*Host, error) {
	const op = "plugin.(hostAgg).toHost"
	const aggregateDelimiter = "|"
	const priorityDelimiter = "="
	h := allocHost()
	h.PublicId = agg.PublicId
	h.CatalogId = agg.CatalogId
	h.ExternalId = agg.ExternalId
	h.PluginId = agg.PluginId
	h.Name = agg.Name
	h.Description = agg.Description
	h.CreateTime = agg.CreateTime
	h.UpdateTime = agg.UpdateTime

	// This function is used to protect against someone messing with the order
	// in the DB by doing some validation
	prioritySortFunc := func(in []string) error {
		var sortErr error
		sort.Slice(in, func(i, j int) bool {
			ini := strings.Split(in[i], priorityDelimiter)
			if len(ini) != 2 {
				sortErr = errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("value %s had unexpected fields", in[i]))
				return false
			}
			inj := strings.Split(in[j], priorityDelimiter)
			if len(inj) != 2 {
				sortErr = errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("value %s had unexpected fields", in[j]))
				return false
			}
			indexi, err := strconv.Atoi(ini[0])
			if err != nil {
				sortErr = errors.Wrap(ctx, err, op)
				return false
			}
			indexj, err := strconv.Atoi(inj[0])
			if err != nil {
				sortErr = errors.Wrap(ctx, err, op)
				return false
			}
			return indexi < indexj
		})
		return sortErr
	}

	if agg.IpAddresses != "" {
		ips := strings.Split(agg.IpAddresses, aggregateDelimiter)
		if len(ips) > 0 {
			if err := prioritySortFunc(ips); err != nil {
				return nil, err
			}
			for i, ip := range ips {
				// At this point they're in the correct order, but we still
				// have to strip off the priority
				ips[i] = strings.Split(ip, priorityDelimiter)[1]
			}
			h.IpAddresses = ips
		}
	}

	if agg.DnsNames != "" {
		names := strings.Split(agg.DnsNames, aggregateDelimiter)
		if len(names) > 0 {
			if err := prioritySortFunc(names); err != nil {
				return nil, err
			}
			for i, name := range names {
				// At this point they're in the correct order, but we still
				// have to strip off the priority
				names[i] = strings.Split(name, priorityDelimiter)[1]
			}
			h.DnsNames = names
		}
	}

	return h, nil
}

// TableName returns the table name for gorm
func (agg *hostAgg) TableName() string {
	return "host_plugin_host_with_value_obj"
}

func (agg *hostAgg) GetPublicId() string {
	return agg.PublicId
}
