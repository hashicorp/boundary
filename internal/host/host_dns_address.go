// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/store"
	"google.golang.org/protobuf/proto"
)

// NOTE: Tests for this are in the plugin subtype directory in host_address_test.go

const defaultDnsNameTableName = "host_dns_name"

type DnsName struct {
	*store.DnsName
	tableName string `gorm:"-"`
}

func NewDnsName(ctx context.Context, hostId string, name string) (*DnsName, error) {
	const op = "host.NewDnsName"
	dn := &DnsName{
		DnsName: &store.DnsName{
			HostId: hostId,
			Name:   name,
		},
	}
	if err := dn.validate(ctx, op); err != nil {
		return nil, err
	}
	return dn, nil
}

// validate the host dns name. On success, it will return nil.
func (dn *DnsName) validate(ctx context.Context, caller errors.Op) error {
	if dn.HostId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing host id")
	}
	if dn.Name == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing dns name")
	}

	return nil
}

// allocDnsName make an empty one in memory.
func allocDnsName() DnsName {
	return DnsName{
		DnsName: &store.DnsName{},
	}
}

// Clone an DnsName
func (c *DnsName) Clone() *DnsName {
	cp := proto.Clone(c.DnsName)
	return &DnsName{
		DnsName: cp.(*store.DnsName),
	}
}

// TableName returns the table name.
func (c *DnsName) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return defaultDnsNameTableName
}

// SetTableName sets the table name.
func (c *DnsName) SetTableName(n string) {
	c.tableName = n
}
