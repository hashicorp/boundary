package static

import (
	"errors"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/host/static/store"
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

func newHostCatalogId() (string, error) {
	return db.NewPublicId("sthc")
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

func newHostId() (string, error) {
	return db.NewPublicId("sth")
}

// A HostSet contains a static address.
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

func newHostSetId() (string, error) {
	return db.NewPublicId("sths")
}

// A HostSet contains a static address.
type HostSetMember struct {
	*store.HostSetMember
	tableName string `gorm:"-"`
}

// NewHostSetMember creates a new in memory HostSetMember assigned to catalogId.
// Name and description are the only valid options. All other options are
// ignored.
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
