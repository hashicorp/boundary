// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tcp

import (
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
)

// Expose functions and variables for tests.
var (
	TestId           = testId
	TestTargetName   = testTargetName
	DefaultTableName = defaultTableName
)

// NewTestTarget is a test helper that bypasses the projectId checks
// performed by NewTarget, allowing tests to create Targets with
// nil projectIds for more robust testing.
func NewTestTarget(projectId string, opt ...target.Option) target.Target {
	t, _ := targetHooks{}.NewTarget("testScope", opt...)
	t.SetProjectId(projectId)
	return t
}

// NewTestAddress is a test helper that bypasses the targetId & address checks
// performed by NewAddress, allowing tests to create a target Address with
// nil fields for more robust testing.
func NewTestAddress() *target.Address {
	return &target.Address{
		TargetAddress: &store.TargetAddress{},
	}
}
