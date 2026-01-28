// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package policy

import "github.com/hashicorp/boundary/internal/boundary"

// Domain defines the domain for this package.
const Domain = "policy"

// Policy contains the common methods across all the different types of policies.
type Policy interface {
	boundary.Resource
	GetScopeId() string
}
