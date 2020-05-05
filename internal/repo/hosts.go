package repo

import "time"

type HostCatalog struct {
	ID           string
	FriendlyName string
	Disabled     bool
	ScopeID      string
	// These values cannot be used to mutate data in storage.
	CreatedTime time.Time
	UpdatedTime time.Time
}
