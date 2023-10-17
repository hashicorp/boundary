// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListCredentialsResponse holds the information returned from ListCredentials and ListCredentialsRefresh
// TODO(johanbrandhorst): Move this into a shared struct when refactoring.
type ListCredentialsResponse struct {
	Items               []Static
	DeletedIds          []string
	EstimatedTotalItems int
	CompleteListing     bool
	RefreshToken        *refreshtoken.Token
}

// ListLibrariesResponse holds the information returned from ListLibraries and ListLibrariesRefresh
// TODO(johanbrandhorst): Move this into a shared struct when refactoring.
type ListLibrariesResponse struct {
	Items               []Library
	DeletedIds          []string
	EstimatedTotalItems int
	CompleteListing     bool
	RefreshToken        *refreshtoken.Token
}

// ListStoresResponse holds the information returned from ListStores and ListStoresRefresh
// TODO(johanbrandhorst): Move this into a shared struct when refactoring.
type ListStoresResponse struct {
	Items               []Store
	DeletedIds          []string
	EstimatedTotalItems int
	CompleteListing     bool
	RefreshToken        *refreshtoken.Token
}
