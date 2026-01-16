// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/store"
	"github.com/hashicorp/boundary/internal/libs/endpoint"
	"google.golang.org/protobuf/proto"
)

// defaultPreferredEndpointTableName defines the default table name for a
// PreferredEndpoint
const defaultPreferredEndpointTableName = "host_set_preferred_endpoint"

// PreferredEndpoint defines an endpoint condition for a host set.
// PreferredEndpoints are value objects of an HostSet, therefore there's no need
// for oplog metadata, since only the HostSet will have metadata because it's
// the root aggregate.
type PreferredEndpoint struct {
	*store.PreferredEndpoint
	tableName string
}

// NewPreferredEndpoint creates a new in memory preferred endpoint assigned to a
// HostSet. It supports no options.
func NewPreferredEndpoint(ctx context.Context, hostSetId string, priority uint32, condition string) (*PreferredEndpoint, error) {
	const op = "host.NewPreferredEndpoint"

	pe := &PreferredEndpoint{
		PreferredEndpoint: &store.PreferredEndpoint{
			HostSetId: hostSetId,
			Priority:  priority,
			Condition: condition,
		},
	}
	if err := pe.validate(ctx, op); err != nil {
		return nil, err // intentionally not wrapped
	}
	return pe, nil
}

// validate the PreferredEndpoint. On success, it will return nil.
func (pe *PreferredEndpoint) validate(ctx context.Context, caller errors.Op) error {
	if pe.HostSetId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing host set id")
	}
	if pe.Priority < 1 {
		return errors.New(ctx, errors.InvalidParameter, caller, "invalid priority value")
	}
	if pe.Condition == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing condition")
	}
	if _, err := endpoint.NewPreferencer(ctx, endpoint.WithPreferenceOrder([]string{pe.Condition})); err != nil {
		return errors.Wrap(ctx, err, caller)
	}

	return nil
}

// AllocPreferredEndpoint makes an empty one in-memory
func AllocPreferredEndpoint() *PreferredEndpoint {
	return &PreferredEndpoint{
		PreferredEndpoint: &store.PreferredEndpoint{},
	}
}

// Clone a PreferredEndpoint
func (pe *PreferredEndpoint) Clone() *PreferredEndpoint {
	cp := proto.Clone(pe.PreferredEndpoint)
	return &PreferredEndpoint{
		PreferredEndpoint: cp.(*store.PreferredEndpoint),
	}
}

// TableName returns the table name.
func (pe *PreferredEndpoint) TableName() string {
	if pe.tableName != "" {
		return pe.tableName
	}
	return defaultPreferredEndpointTableName
}

// SetTableName sets the table name.
func (pe *PreferredEndpoint) SetTableName(n string) {
	pe.tableName = n
}
