// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package targets

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/daemon/common"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/target/targettest"
	"github.com/hashicorp/boundary/internal/target/targettest/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerList_Addresses(t *testing.T) {
	addresses := []string{
		"test1",
		"test2",
		"test3",
		"test4",
	}
	var workerInfos []*pb.WorkerInfo
	var tested common.WorkerList
	for _, a := range addresses {
		workerInfos = append(workerInfos, &pb.WorkerInfo{Address: a})
		tested = append(tested, server.NewWorker(scope.Global.String(),
			server.WithName(a),
			server.WithAddress(a)))
	}
	assert.Equal(t, addresses, tested.Addresses())
	assert.Equal(t, workerInfos, tested.WorkerInfos())
}

func TestWorkerList_EgressFilter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	SetupSuiteTargetFilters(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	var workers []*server.Worker
	for i := 0; i < 5; i++ {
		switch {
		case i%2 == 0:
			workers = append(workers, server.TestKmsWorker(t, conn, wrapper,
				server.WithName(fmt.Sprintf("test_worker_%d", i)),
				server.WithWorkerTags(&server.Tag{
					Key:   fmt.Sprintf("key%d", i),
					Value: fmt.Sprintf("value%d", i),
				})))
		default:
			workers = append(workers, server.TestPkiWorker(t, conn, wrapper,
				server.WithName(fmt.Sprintf("test_worker_%d", i)),
				server.WithWorkerTags(&server.Tag{
					Key:   "key",
					Value: "configvalue",
				})))
		}
	}

	cases := []struct {
		name        string
		in          []*server.Worker
		out         []*server.Worker
		filter      string
		errContains string
	}{
		{
			name:        "no-workers",
			in:          []*server.Worker{},
			out:         []*server.Worker{},
			filter:      "",
			errContains: "No workers are available to handle this session, or all have been filtered",
		},
		{
			name: "no-filter",
			in:   workers,
			out:  workers,
		},
		{
			name:        "filter-no-matches",
			in:          workers,
			out:         workers,
			filter:      `"/name" matches "test_worker_[13]" and "configvalue2" in "/tags/key"`,
			errContains: "No workers are available to handle this session, or all have been filtered",
		},
		{
			name:   "filter-one-match",
			in:     workers,
			out:    []*server.Worker{workers[1]},
			filter: `"/name" matches "test_worker_[12]" and "configvalue" in "/tags/key"`,
		},
		{
			name:   "filter-two-matches",
			in:     workers,
			out:    []*server.Worker{workers[1], workers[3]},
			filter: `"configvalue" in "/tags/key"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			target := &targettest.Target{
				Target: &store.Target{},
			}
			if len(tc.filter) > 0 {
				target.EgressWorkerFilter = tc.filter
			}
			out, protocolWorker, err := AuthorizeSessionWithWorkerFilter(ctx, target, tc.in, "", nil, nil)
			if tc.errContains != "" {
				assert.Contains(err.Error(), tc.errContains)
				assert.Nil(out)
				return
			}

			require.NoError(err)
			require.Len(out, len(tc.out))
			for i, exp := range tc.out {
				assert.Equal(exp.Name, out[i].Name)
			}
			require.Nil(protocolWorker)
		})
	}
}
