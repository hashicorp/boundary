// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
)

func (et Type) Validate() error {
	const op = "event.(Type).Validate"
	switch et {
	case EveryType, ObservationType, AuditType, ErrorType, SystemType:
		return nil
	default:
		return fmt.Errorf("%s: '%s' is not a valid event type: %w", op, et, ErrInvalidParameter)
	}
}
