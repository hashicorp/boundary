// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package globals

import (
	"context"
	"net/netip"
)

// ControllerExtension defines the interface implemented
// by the enterprise controller extension. This type
// can be used to pass the controller extension into
// handlers and repositories.
type ControllerExtension interface {
	Start(context.Context) error
}

// This is an interface satisfied by net.DefaultResolver but can be replaced for
// tests
type NetIpResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
