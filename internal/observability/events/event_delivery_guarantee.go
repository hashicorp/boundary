package event

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
)

const (
	DefaultDeliveryGuarantee DeliveryGuarantee = ""            // DefaultDeliveryGuarantee will be BestEffort
	Enforced                 DeliveryGuarantee = "enforced"    // Enforced means that a delivery guarantee is enforced
	BestEffort               DeliveryGuarantee = "best-effort" // BestEffort means that a best effort will be made to deliver an event
)

type DeliveryGuarantee string // DeliveryGuarantee defines the guarantees around delivery of an event type within config

func (g DeliveryGuarantee) validate() error {
	const op = "event.(DeliveryGuarantee"
	switch g {
	case DefaultDeliveryGuarantee, BestEffort, Enforced:
		return nil
	default:
		return errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s is not a valid delivery guarantee", g))
	}
}
