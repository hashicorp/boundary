package controller_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
)

// This test has to live on this level because it depends on us importing all packages that
// need to register a rewrapping fn. This is the top level package
// for the controller, and will include all packages (directly or transitively),
// so any packages that will register a rewrapping fn should have been imported here.
func TestAllDataKeyReferencersHaveARewrappingFn(t *testing.T) {
	ctx := context.Background()
	tc := controller.NewTestController(t, nil)
	t.Cleanup(tc.Shutdown)
	tableNames, err := tc.Kms().ListDataKeyVersionReferencers(ctx)
	require.NoError(t, err)
	// We don't care about these tables
	i := slices.Index(tableNames, "oplog_entry")
	slices.Delete(tableNames, i, i+1)
	i = slices.Index(tableNames, "kms_data_key_version_destruction_job")
	slices.Delete(tableNames, i, i+1)
	registeredTableNames := kms.ListTablesSupportingRewrap()
	require.Empty(t, cmp.Diff(tableNames, registeredTableNames, cmpopts.SortSlices(func(i, j string) bool { return i < j })), "At least one table referencing a data key does not have a rewrapping function registered")
}
