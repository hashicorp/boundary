// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package globals

import (
	"context"
)

// ControllerExtension defines the interface implemented
// by the enterprise controller extension. This type
// can be used to pass the controller extension into
// handlers and repositories.
type ControllerExtension interface {
	Start(context.Context) error
}
