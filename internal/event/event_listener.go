// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"context"

	"github.com/hashicorp/eventlogger"
)

// EventHandlerFunc is a function that handles an event.
type EventHandlerFunc func(ctx context.Context, e *eventlogger.Event)

// EventListener is an interface for listening to events.
type EventListener interface {
	// RegisterEventHandlerFunc registers an event handler function for the given event type.
	// A given event type can have multiple event handler functions registered.
	RegisterEventHandlerFunc(ctx context.Context, ev Type, ehf EventHandlerFunc) error
	// Start starts the event listener.
	Start(ctx context.Context) error
	// Shutdown stops the event listener.
	Shutdown(ctx context.Context) error
}
