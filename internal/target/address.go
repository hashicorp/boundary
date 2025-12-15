// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"net"
	"regexp"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultTargetAddressTableName = "target_address"
)

// An Address represents the relationship between a target and a
// network address.
type Address struct {
	*store.TargetAddress
	tableName string `gorm:"-"`
}

// Ensure Address implements interfaces
var (
	_ db.VetForWriter         = (*Address)(nil)
	_ oplog.ReplayableMessage = (*Address)(nil)
)

var (
	labelRegex   = regexp.MustCompile(`^[a-zA-Z0-9-]{1,63}$`)
	numbersRegex = regexp.MustCompile(`^\d+$`)
)

// DNS names consists of at least one label joined together by a "."
// Each label can consist of a-z 0-9 and "-" case insensitive
// A label cannot start or end with a "-"
// A label can be between 1 and 63 characters long
// The final label in the dns name cannot be all numeric
// See https://en.wikipedia.org/wiki/Domain_Name_System#Domain_name_syntax,_internationalization
func isValidDnsName(name string) bool {
	// Trim any trailing dot, otherwise a name like "thing." will split to ["thing", ""] and return false for the empty label
	name = strings.Trim(name, ".")
	labels := strings.Split(name, ".")
	if len(labels) == 0 {
		return false
	}
	for i, label := range labels {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		if !labelRegex.MatchString(label) {
			return false
		}
		// Last label cannot be all numeric
		if i == len(labels)-1 {
			if numbersRegex.MatchString(label) {
				return false
			}
		}
	}
	return true
}

// Current addresses supported are IPv4, IPv6 addresses
// or DNS names. More may be supported in the future.
func isValidAddress(address string) bool {
	// Try to split host and port
	_, _, splitErr := net.SplitHostPort(address)
	if splitErr == nil {
		return true
	}
	ip := net.ParseIP(address)
	if ip != nil {
		return true
	}
	return isValidDnsName(address)
}

// NewAddress creates a new in memory address. No options are
// currently supported.
func NewAddress(ctx context.Context, targetId, address string, _ ...Option) (*Address, error) {
	const op = "target.NewAddress"
	if targetId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if address == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing address")
	}
	address = strings.TrimSpace(address)
	if !isValidAddress(address) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid address")
	}
	t := &Address{
		TargetAddress: &store.TargetAddress{
			TargetId: targetId,
			Address:  address,
		},
	}
	return t, nil
}

// Clone creates a clone of the target address
func (t *Address) Clone() any {
	cp := proto.Clone(t.TargetAddress)
	return &Address{
		TargetAddress: cp.(*store.TargetAddress),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the target
// address before it's written.
func (t *Address) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "target.(Address).VetForWrite"
	if opType == db.CreateOp {
		if t.GetTargetId() == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing target id")
		}
		if t.GetAddress() == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing address")
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (t *Address) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return DefaultTargetAddressTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (t *Address) SetTableName(n string) {
	t.tableName = n
}

func (t *Address) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{t.GetTargetId()},
		"resource-type":      []string{"target address"},
		"op-type":            []string{op.String()},
	}
	return metadata
}

func (t *Address) TargetId() string {
	return t.GetTargetId()
}

func (t *Address) Address() string {
	return t.GetAddress()
}

func (t *Address) GetPublicId() string {
	return t.GetTargetId()
}

// allocTargetAddress will allocate a address
func allocTargetAddress() *Address {
	return &Address{
		TargetAddress: &store.TargetAddress{},
	}
}
