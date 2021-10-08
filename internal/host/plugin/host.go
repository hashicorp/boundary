package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A Host is a temporarily cached plugin based resource.  The source of truth
// of the data contained here is provided by the service backing the plugin for
// this host.  The plugin for this host can be found by looking at the plugin
// field for this host's host catalog.
type Host struct {
	*store.Host
	tableName string `gorm:"-"`
}

// newHost creates a new in memory Host assigned to catalogId with an address.
// Name and description are the only valid options. All other options are
// ignored.
func newHost(ctx context.Context, catalogId, externalId string, opt ...Option) *Host {
	opts := getOpts(opt...)

	h := &Host{
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
	if len(opts.withDnsAddresses) > 0 {
		h.DnsAddresses = make([]string, 0, len(opts.withDnsAddresses))
		h.DnsAddresses = append(h.DnsAddresses, opts.withDnsAddresses...)
	}

	return h
}

// convertDnsAddresses converts the embedded dns addresses from []string to
// []interface{} where each slice element is a *HostDnsAddress. It will return
// an error if the Host's public id is not set.
func (s *Host) convertDnsAddresses(ctx context.Context) ([]interface{}, error) {
	const op = "plugin.(Host).convertDnsAddresses"
	if s.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	newInterfaces := make([]interface{}, 0, len(s.DnsAddresses))
	for _, a := range s.DnsAddresses {
		obj := newHostDnsAddress(ctx, s.PublicId, a)
		newInterfaces = append(newInterfaces, obj)
	}
	return newInterfaces, nil
}

// convertIpAddresses converts the embedded ip addresses from []string to
// []interface{} where each slice element is a *HostIpAddress. It will return
// an error if the Host's public id is not set.
func (s *Host) convertIpAddresses(ctx context.Context) ([]interface{}, error) {
	const op = "plugin.(Host).convertIpAddresses"
	if s.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	newInterfaces := make([]interface{}, 0, len(s.IpAddresses))
	for _, a := range s.IpAddresses {
		obj := newHostIpAddress(ctx, s.PublicId, a)
		newInterfaces = append(newInterfaces, obj)
	}
	return newInterfaces, nil
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

func (s *Host) clone() *Host {
	cp := proto.Clone(s.Host)
	hs := &Host{
		Host: cp.(*store.Host),
	}
	return hs
}

func (s *Host) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{s.PublicId},
		"resource-type":      []string{"plugin-host"},
		"op-type":            []string{op.String()},
	}
	if s.CatalogId != "" {
		metadata["catalog-id"] = []string{s.CatalogId}
	}
	return metadata
}
