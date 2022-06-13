package tcp

import "github.com/hashicorp/boundary/internal/target"

// Expose functions and variables for tests.
var (
	TestId           = testId
	TestTargetName   = testTargetName
	DefaultTableName = defaultTableName
)

// NewTestTarget is a test helper that bypasses the scopeId checks
// performed by NewTarget, allowing tests to create Targets with
// nil scopeIds for more robust testing.
func NewTestTarget(scopeId string, opt ...target.Option) target.Target {
	t, _ := targetHooks{}.NewTarget("testScope", opt...)
	t.SetScopeId(scopeId)
	return t
}
