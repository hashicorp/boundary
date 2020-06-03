package static

import (
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/host/static/store"
	"google.golang.org/protobuf/proto"
)

// A HostCatalog contains static hosts and static host sets. It is owned by
// a scope.
type HostCatalog struct {
	*store.HostCatalog
	tableName string `gorm:"-"`
}

// NewHostCatalog creates a new in memory HostCatalog assigned to scopeId.
// Name and description are the only valid options. All other options are
// ignored.
func NewHostCatalog(scopeId string, opt ...Option) (*HostCatalog, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("new: static host catalog: no scope id: %w", db.ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	hc := &HostCatalog{
		HostCatalog: &store.HostCatalog{
			ScopeId:     scopeId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	return hc, nil
}

func (c *HostCatalog) clone() *HostCatalog {
	cp := proto.Clone(c.HostCatalog)
	return &HostCatalog{
		HostCatalog: cp.(*store.HostCatalog),
	}
}

// A Host contains a static address.
type Host struct {
	*store.Host
	tableName string `gorm:"-"`
}

// NewHost creates a new in memory Host for address assigned to catalogId.
// Name and description are the only valid options. All other options are
// ignored.
func NewHost(catalogId, address string, opt ...Option) (*Host, error) {
	if catalogId == "" {
		return nil, fmt.Errorf("new: static host: no catalog id: %w", db.ErrInvalidParameter)
	}
	if address == "" {
		return nil, fmt.Errorf("new: static host: no address: %w", db.ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	host := &Host{
		Host: &store.Host{
			StaticHostCatalogId: catalogId,
			Address:             address,
			Name:                opts.withName,
			Description:         opts.withDescription,
		},
	}
	return host, nil
}

func (c *Host) clone() *Host {
	cp := proto.Clone(c.Host)
	return &Host{
		Host: cp.(*store.Host),
	}
}

// A HostSet is a collection of hosts from the set's catalog.
type HostSet struct {
	*store.HostSet
	tableName string `gorm:"-"`
}

// NewHostSet creates a new in memory HostSet assigned to catalogId.
// Name and description are the only valid options. All other options are
// ignored.
func NewHostSet(catalogId string, opt ...Option) (*HostSet, error) {
	if catalogId == "" {
		return nil, fmt.Errorf("new: static host set: no catalog id: %w", db.ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	set := &HostSet{
		HostSet: &store.HostSet{
			StaticHostCatalogId: catalogId,
			Name:                opts.withName,
			Description:         opts.withDescription,
		},
	}
	return set, nil
}

// A HostSetMember represents the membership of a host in a host set.
type HostSetMember struct {
	*store.HostSetMember
	tableName string `gorm:"-"`
}

// NewHostSetMember creates a new in memory HostSetMember representing the
// membership of hostId in hostSetId.
func NewHostSetMember(hostSetId, hostId string, opt ...Option) (*HostSetMember, error) {
	if hostSetId == "" {
		return nil, fmt.Errorf("new: static host set member: no host set id: %w", db.ErrInvalidParameter)
	}
	if hostId == "" {
		return nil, fmt.Errorf("new: static host set member: no host id: %w", db.ErrInvalidParameter)
	}
	member := &HostSetMember{
		HostSetMember: &store.HostSetMember{
			StaticHostSetId: hostSetId,
			StaticHostId:    hostId,
		},
	}
	return member, nil
}

// PublicId prefixes for the resources in the static package.
const (
	HostCatalogPrefix = "sthc"
	HostSetPrefix     = "sths"
	HostPrefix        = "sth"
)

func newHostCatalogId() (string, error) {
	id, err := db.NewPublicId(HostCatalogPrefix)
	if err != nil {
		return "", fmt.Errorf("new host catalog id: %w", err)
	}
	return id, err
}

func newHostId() (string, error) {
	id, err := db.NewPublicId(HostPrefix)
	if err != nil {
		return "", fmt.Errorf("new host id: %w", err)
	}
	return id, err
}

func newHostSetId() (string, error) {
	id, err := db.NewPublicId(HostSetPrefix)
	if err != nil {
		return "", fmt.Errorf("new host set id: %w", err)
	}
	return id, err
}
