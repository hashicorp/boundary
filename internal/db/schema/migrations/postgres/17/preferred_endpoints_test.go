package migration

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PreferredEndpointTable(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	rootWrapper := db.TestWrapper(t)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	hc := static.TestCatalogs(t, conn, proj.PublicId, 1)[0]
	hs := static.TestSets(t, conn, hc.PublicId, 1)[0]

	type testCondition struct {
		condition string
		priority  uint32
	}
	insertTests := []struct {
		testName        string
		hostSetId       string
		conditions      []testCondition
		wantErrContains string
	}{
		{
			testName:  "invalid host set id",
			hostSetId: "hsst_1234567890",
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dns:abcd",
				},
				{
					priority:  2,
					condition: "cidr:1.2.3.4",
				},
			},
			wantErrContains: "host_set_fkey",
		},
		{
			testName:  "invalid condition prefix",
			hostSetId: hs.PublicId,
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dsn:abcd",
				},
			},
			wantErrContains: "condition_has_valid_prefix",
		},
		{
			testName:  "invalid condition length",
			hostSetId: hs.PublicId,
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dns:",
				},
			},
			wantErrContains: "condition_must_not_be_too_short",
		},
		{
			testName:  "invalid priority",
			hostSetId: hs.PublicId,
			conditions: []testCondition{
				{
					priority:  0,
					condition: "dns:abcd",
				},
			},
			wantErrContains: "priority_must_be_greater_than_zero",
		},
		{
			testName:  "duplicate priority",
			hostSetId: hs.PublicId,
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dns:abcd",
				},
				{
					priority:  1,
					condition: "cidr:1.2.3.4",
				},
			},
			wantErrContains: "host_set_preferred_endpoint_pkey",
		},
		{
			testName:  "invalid char 1",
			hostSetId: hs.PublicId,
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dns:ab|cd",
				},
				{
					priority:  1,
					condition: "cidr:1.2.3.4",
				},
			},
			wantErrContains: "condition_does_not_contain_invalid_chars",
		},
		{
			testName:  "invalid char 2",
			hostSetId: hs.PublicId,
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dns:abcd",
				},
				{
					priority:  1,
					condition: "cidr:1.2=.3.4",
				},
			},
			wantErrContains: "condition_does_not_contain_invalid_chars",
		},
		{
			testName:  "valid",
			hostSetId: hs.PublicId,
			conditions: []testCondition{
				{
					priority:  1,
					condition: "dns:abcd",
				},
				{
					priority:  2,
					condition: "cidr:1.2.3.4",
				},
			},
		},
	}
	for _, tt := range insertTests {
		t.Run("insert: "+tt.testName, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, err := rw.Exec(ctx, "delete from host_set_preferred_endpoint where host_set_id = ?", []interface{}{tt.hostSetId})
			require.NoError(err)

			// Add items to insert
			var items []interface{}
			for _, cond := range tt.conditions {
				ep := host.AllocPreferredEndpoint()
				ep.HostSetId = tt.hostSetId
				ep.Condition = cond.condition
				ep.Priority = cond.priority
				items = append(items, ep)
			}
			err = rw.CreateItems(ctx, items)
			if tt.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(err)
		})
	}
}
