// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

// A HostSet is a collection of hosts from the set's catalog.
type HostSet struct {
	*store.HostSet
	PluginId           string   `gorm:"-"`
	HostIds            []string `gorm:"-"`
	PreferredEndpoints []string `gorm:"-"`
	tableName          string   `gorm:"-"`
}

// NewHostSet creates a new in memory HostSet assigned to catalogId. Attributes,
// name, description, and preferred endpoints are the only valid options. All
// other options are ignored.
func NewHostSet(ctx context.Context, catalogId string, opt ...Option) (*HostSet, error) {
	const op = "plugin.NewHostSet"
	opts := getOpts(opt...)
	attrs, err := proto.Marshal(opts.withAttributes)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}

	set := &HostSet{
		HostSet: &store.HostSet{
			CatalogId:           catalogId,
			Name:                opts.withName,
			Description:         opts.withDescription,
			SyncIntervalSeconds: opts.withSyncIntervalSeconds,
			Attributes:          attrs,
		},
		PreferredEndpoints: opts.withPreferredEndpoints,
	}

	return set, nil
}

// TableName returns the table name for the host set.
func (s *HostSet) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return "host_plugin_set"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (s *HostSet) SetTableName(n string) {
	s.tableName = n
}

// GetResourceType returns the resource type of the HostSet
func (s *HostSet) GetResourceType() resource.Type {
	return resource.HostSet
}

func allocHostSet() *HostSet {
	return &HostSet{
		HostSet: &store.HostSet{},
	}
}

func (s *HostSet) clone() *HostSet {
	cp := proto.Clone(s.HostSet)
	hs := &HostSet{
		HostSet:            cp.(*store.HostSet),
		PreferredEndpoints: s.PreferredEndpoints,
	}
	if s.Attributes != nil && len(s.Attributes) == 0 && hs.Attributes == nil {
		hs.Attributes = []byte{}
	}
	return hs
}

func (s *HostSet) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{s.PublicId},
		"resource-type":      []string{"plugin-host-set"},
		"op-type":            []string{op.String()},
	}
	if s.CatalogId != "" {
		metadata["catalog-id"] = []string{s.CatalogId}
	}
	return metadata
}

// hostSetAgg is a view that aggregates the host set's value objects in to
// string fields delimited with the aggregateDelimiter of "|"
type hostSetAgg struct {
	PublicId            string `gorm:"primary_key"`
	CatalogId           string
	PluginId            string
	Name                string
	Description         string
	CreateTime          *timestamp.Timestamp
	UpdateTime          *timestamp.Timestamp
	LastSyncTime        *timestamp.Timestamp
	NeedSync            bool
	SyncIntervalSeconds int32
	Version             uint32
	Attributes          []byte
	PreferredEndpoints  string
	HostIds             string
}

func (agg *hostSetAgg) toHostSet(ctx context.Context) (*HostSet, error) {
	const op = "plugin.(hostSetAgg).toHostSet"
	const aggregateDelimiter = "|"
	const priorityDelimiter = "="
	hs := allocHostSet()
	hs.PublicId = agg.PublicId
	hs.CatalogId = agg.CatalogId
	hs.PluginId = agg.PluginId
	hs.Name = agg.Name
	hs.Description = agg.Description
	hs.CreateTime = agg.CreateTime
	hs.UpdateTime = agg.UpdateTime
	hs.LastSyncTime = agg.LastSyncTime
	hs.NeedSync = agg.NeedSync
	hs.SyncIntervalSeconds = agg.SyncIntervalSeconds
	hs.Version = agg.Version
	hs.Attributes = agg.Attributes
	if agg.HostIds != "" {
		hs.HostIds = strings.Split(agg.HostIds, aggregateDelimiter)
	}
	if agg.PreferredEndpoints != "" {
		eps := strings.Split(agg.PreferredEndpoints, aggregateDelimiter)
		if len(eps) > 0 {
			// We want to protect against someone messing with the DB
			// and not panic, so we do a bit of a dance here
			var sortErr error
			sort.Slice(eps, func(i, j int) bool {
				epi := strings.Split(eps[i], priorityDelimiter)
				if len(epi) != 2 {
					sortErr = errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("preferred endpoint %s had unexpected fields", eps[i]))
					return false
				}
				epj := strings.Split(eps[j], priorityDelimiter)
				if len(epj) != 2 {
					sortErr = errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("preferred endpoint %s had unexpected fields", eps[j]))
					return false
				}
				indexi, err := strconv.Atoi(epi[0])
				if err != nil {
					sortErr = errors.Wrap(ctx, err, op)
					return false
				}
				indexj, err := strconv.Atoi(epj[0])
				if err != nil {
					sortErr = errors.Wrap(ctx, err, op)
					return false
				}
				return indexi < indexj
			})
			if sortErr != nil {
				return nil, sortErr
			}
			for i, ep := range eps {
				// At this point they're in the correct order, but we still
				// have to strip off the priority
				eps[i] = strings.Split(ep, priorityDelimiter)[1]
			}
			hs.PreferredEndpoints = eps
		}
	}
	return hs, nil
}

func (agg *hostSetAgg) GetPublicId() string {
	return agg.PublicId
}

// TableName returns the table name for gorm
func (agg *hostSetAgg) TableName() string {
	return "host_plugin_host_set_with_value_obj"
}

type deletedHostSet struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedHostSet) TableName() string {
	return "host_plugin_set_deleted"
}
