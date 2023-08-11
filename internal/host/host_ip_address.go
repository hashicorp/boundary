// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"context"
	"net"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/store"
	"google.golang.org/protobuf/proto"
)

// NOTE: Tests for this are in the plugin subtype directory in host_address_test.go

const defaultIpAddressTableName = "host_ip_address"

type IpAddress struct {
	*store.IpAddress
	tableName string `gorm:"-"`
}

func NewIpAddress(ctx context.Context, hostId string, address string) (*IpAddress, error) {
	const op = "host.NewIpAddress"

	ia := &IpAddress{
		IpAddress: &store.IpAddress{
			HostId:  hostId,
			Address: address,
		},
	}
	if err := ia.validate(ctx, op); err != nil {
		return nil, err
	}
	return ia, nil
}

// validate the host ip address. On success, it will return nil.
func (ia *IpAddress) validate(ctx context.Context, caller errors.Op) error {
	if ia.HostId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing host id")
	}
	if ia.Address == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing ip address")
	}
	if ip := net.ParseIP(ia.Address); ip == nil {
		return errors.New(ctx, errors.InvalidParameter, caller, "given address is not an ip address")
	}

	return nil
}

// allocIpAddress make an empty one in memory.
func allocIpAddress() IpAddress {
	return IpAddress{
		IpAddress: &store.IpAddress{},
	}
}

// Clone an IpAddress
func (c *IpAddress) Clone() *IpAddress {
	cp := proto.Clone(c.IpAddress)
	return &IpAddress{
		IpAddress: cp.(*store.IpAddress),
	}
}

// TableName returns the table name.
func (c *IpAddress) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return defaultIpAddressTableName
}

// SetTableName sets the table name.
func (c *IpAddress) SetTableName(n string) {
	c.tableName = n
}
