// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"fmt"
)

// Type represents the event's type
type Type string

const (
	EveryType       Type = "*"           // EveryType represents every (all) types of events
	ObservationType Type = "observation" // ObservationType represents observation events
	AuditType       Type = "audit"       // AuditType represents audit events
	ErrorType       Type = "error"       // ErrorType represents error events
	SystemType      Type = "system"      // SysType represents system events
	StorageType     Type = "storage"     // StorageType represents storage events
	TelemetryType   Type = "telemetry"   // TelemetryType represents telemetry events
)

func (et Type) Validate() error {
	const op = "event.(Type).Validate"
	switch et {
	case EveryType, ObservationType, AuditType, ErrorType, SystemType, StorageType, TelemetryType:
		return nil
	default:
		return fmt.Errorf("%s: '%s' is not a valid event type: %w", op, et, ErrInvalidParameter)
	}
}
