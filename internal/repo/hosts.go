package repo

import "time"

// TODO: Handle masking for updates (and maybe for views)
type Host struct {
	ID           string
	FriendlyName string
	Disabled     bool
	Address      string
	// These values cannot be used to mutate data in storage.
	CreateTime time.Time
	UpdateTime time.Time
}

type HostCatalog struct {
	ID           string
	FriendlyName string
	Disabled     bool
	ScopeID      string
	// These values cannot be used to mutate data in storage.
	CreateTime time.Time
	UpdateTime time.Time
}

type HostSet struct {
	ID           string
	FriendlyName string
	Disabled     bool
	Hosts        []Host
	// These values cannot be used to mutate data in storage.
	Size       int64
	CreateTime time.Time
	UpdateTime time.Time
}
