// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"fmt"
)

const (
	DefaultDeliveryGuarantee DeliveryGuarantee = ""            // DefaultDeliveryGuarantee will be BestEffort
	Enforced                 DeliveryGuarantee = "enforced"    // Enforced means that a delivery guarantee is enforced
	BestEffort               DeliveryGuarantee = "best-effort" // BestEffort means that a best effort will be made to deliver an event
)

type DeliveryGuarantee string // DeliveryGuarantee defines the guarantees around delivery of an event type within config

func (g DeliveryGuarantee) validate() error {
	const op = "event.(DeliveryGuarantee).validate"
	switch g {
	case DefaultDeliveryGuarantee, BestEffort, Enforced:
		return nil
	default:
		return fmt.Errorf("%s: %s is not a valid delivery guarantee: %w", op, g, ErrInvalidParameter)
	}
}
