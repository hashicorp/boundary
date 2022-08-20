package controller_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
)

// This test has to live on this level because it depends on us importing all packages that
// need to register a rewrapping fn. This is the top level package
// for the controller, and will include all packages (directly or transitively),
// so any packages that will register a rewrapping fn should have been imported here.
func TestAllDataKeyReferencersHaveARewrappingFn(t *testing.T) {
	ctx := context.Background()
	tc := controller.NewTestController(t, nil)
	t.Cleanup(tc.Shutdown)
	tableNames, err := tc.Kms().ListDataKeyReferencers(ctx)
	require.NoError(t, err)
	registeredTableNames := kms.ListTablesSupportingRewrap()
	require.Empty(t, cmp.Diff(tableNames, registeredTableNames, cmpopts.SortSlices(func(i, j string) bool { return i < j })), "At least one table referencing a data key does not have a rewrapping function registered")
}
