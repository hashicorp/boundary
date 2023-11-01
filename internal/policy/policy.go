// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package policy

import "github.com/hashicorp/boundary/internal/boundary"

// Policy contains the common methods across all the different types of policies.
type Policy interface {
	boundary.Resource
	GetScopeId() string
}
