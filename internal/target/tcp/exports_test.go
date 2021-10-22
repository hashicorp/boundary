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
func NewTestTarget(scopeId string, opt ...target.Option) *Target {
	t, _ := New("testScope", opt...)
	t.ScopeId = scopeId
	return t
}
