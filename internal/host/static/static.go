package static

import (
	"errors"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/host/static/store"
	"google.golang.org/protobuf/proto"
)

// A HostCatalog contains static hosts and static host sets.
type HostCatalog struct {
	*store.HostCatalog
	tableName string `gorm:"-"`
}

// NewHostCatalog creates a new in memory HostCatalog assigned to scopeId.
// Name and description are the only valid options. All other options are
// ignored.
func NewHostCatalog(scopeId string, opt ...Option) (*HostCatalog, error) {
	if scopeId == "" {
		return nil, errors.New("empty scopeId")
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
		return nil, errors.New("empty catalogId")
	}
	if address == "" {
		return nil, errors.New("empty address")
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
		return nil, errors.New("empty catalogId")
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
		return nil, errors.New("empty hostSetId")
	}
	if hostId == "" {
		return nil, errors.New("empty hostId")
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
	hostCatalogPrefix = "sthc"
	hostSetPrefix     = "sths"
	hostPrefix        = "sth"
)

func newHostCatalogId() (string, error) {
	return db.NewPublicId(hostCatalogPrefix)
}

func newHostId() (string, error) {
	return db.NewPublicId(hostPrefix)
}

func newHostSetId() (string, error) {
	return db.NewPublicId(hostSetPrefix)
}
