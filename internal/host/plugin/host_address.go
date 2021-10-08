package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"google.golang.org/protobuf/proto"
)

const defaultHostDnsAddressTableName = "host_plugin_host_dns_address"

type HostDnsAddress struct {
	*store.HostAddress
	tableName string `gorm:"-"`
}

func newHostDnsAddress(ctx context.Context, hostId, address string) *HostDnsAddress {
	const op = "plugin.newHostDnsAddress"
	ha := &HostDnsAddress{
		HostAddress: &store.HostAddress{
			HostId:  hostId,
			Address: address,
		},
	}
	return ha
}

// allocHostDnsAddress make an empty one in memory.
func allocHostDnsAddress() HostDnsAddress {
	return HostDnsAddress{
		HostAddress: &store.HostAddress{},
	}
}

// Clone an HostDnsAddress
func (c *HostDnsAddress) Clone() *HostDnsAddress {
	cp := proto.Clone(c.HostAddress)
	return &HostDnsAddress{
		HostAddress: cp.(*store.HostAddress),
	}
}

// TableName returns the table name.
func (c *HostDnsAddress) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return defaultHostDnsAddressTableName
}

// SetTableName sets the table name.
func (c *HostDnsAddress) SetTableName(n string) {
	c.tableName = n
}

const defaultHostIpAddressTableName = "host_plugin_host_ip_address"

type HostIpAddress struct {
	*store.HostAddress
	tableName string `gorm:"-"`
}

func newHostIpAddress(ctx context.Context, hostId, address string) *HostIpAddress {
	const op = "plugin.newHostIpAddress"
	ha := &HostIpAddress{
		HostAddress: &store.HostAddress{
			HostId:  hostId,
			Address: address,
		},
	}
	return ha
}

// allocHostIpAddress make an empty one in memory.
func allocHostIpAddress() HostIpAddress {
	return HostIpAddress{
		HostAddress: &store.HostAddress{},
	}
}

// Clone an HostIpAddress
func (c *HostIpAddress) Clone() *HostIpAddress {
	cp := proto.Clone(c.HostAddress)
	return &HostIpAddress{
		HostAddress: cp.(*store.HostAddress),
	}
}

// TableName returns the table name.
func (c *HostIpAddress) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return defaultHostIpAddressTableName
}

// SetTableName sets the table name.
func (c *HostIpAddress) SetTableName(n string) {
	c.tableName = n
}
