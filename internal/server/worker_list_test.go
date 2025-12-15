// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"math/rand/v2"
	"strconv"
	"testing"

	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerList_FilterWorkersByLocalStorageState(t *testing.T) {
	t.Run("list of workers with unhealthy workers", func(t *testing.T) {
		workers := WorkerList([]*Worker{
			NewWorker("global",
				WithName("worker1"),
				WithReleaseVersion("Boundary v0.16.0"),
				WithLocalStorageState(AvailableLocalStorageState.String())),
			NewWorker("global",
				WithName("worker2"),
				WithReleaseVersion("Boundary v0.16.0"),
				WithLocalStorageState(LowStorageLocalStorageState.String())),
			NewWorker("global",
				WithName("worker3"),
				WithReleaseVersion("Boundary v0.16.0"),
				WithLocalStorageState(CriticallyLowStorageLocalStorageState.String())),
		})

		healthyWorkers := FilterWorkersByLocalStorageState(workers)
		assert.Equal(t, 1, len(healthyWorkers))
	})

	t.Run("list of workers with some unsupported worker versions", func(t *testing.T) {
		workers := WorkerList([]*Worker{
			NewWorker("global",
				WithName("worker1"),
				WithReleaseVersion("Boundary v0.16.0"),
				WithLocalStorageState(AvailableLocalStorageState.String())),
			NewWorker("global",
				WithName("worker2"),
				WithReleaseVersion("Boundary v0.16.0"),
				WithLocalStorageState(UnknownLocalStorageState.String())),
			NewWorker("global",
				WithName("worker3"),
				WithReleaseVersion("Boundary v0.16.0"),
				WithLocalStorageState(CriticallyLowStorageLocalStorageState.String())),
			NewWorker("global",
				WithName("worker4"),
				WithReleaseVersion("Boundary v0.15.0"),
				WithLocalStorageState(CriticallyLowStorageLocalStorageState.String())),
		})

		healthyWorkers := FilterWorkersByLocalStorageState(workers)
		assert.Equal(t, 2, len(healthyWorkers))
	})

	t.Run("list of workers with no healthy workers", func(t *testing.T) {
		workers := WorkerList([]*Worker{
			NewWorker("global",
				WithName("worker1"),
				WithReleaseVersion("Boundary v0.16.0"),
				WithLocalStorageState(LowStorageLocalStorageState.String())),
			NewWorker("global",
				WithName("worker2"),
				WithReleaseVersion("Boundary v0.16.0"),
				WithLocalStorageState(OutOfStorageLocalStorageState.String())),
			NewWorker("global",
				WithName("worker3"),
				WithReleaseVersion("Boundary v0.16.0"),
				WithLocalStorageState(CriticallyLowStorageLocalStorageState.String())),
		})

		healthyWorkers := FilterWorkersByLocalStorageState(workers)
		assert.Equal(t, 0, len(healthyWorkers))
	})

	t.Run("list of workers with all unknown local storage state", func(t *testing.T) {
		workers := WorkerList([]*Worker{
			NewWorker("global",
				WithName("worker1"),
				WithReleaseVersion("Boundary v0.16.0"),
				WithLocalStorageState(UnknownLocalStorageState.String())),
			NewWorker("global",
				WithName("worker2"),
				WithReleaseVersion("Boundary v0.16.0"),
				WithLocalStorageState(UnknownLocalStorageState.String())),
			NewWorker("global",
				WithName("worker3"),
				WithReleaseVersion("Boundary v0.16.0"),
				WithLocalStorageState(UnknownLocalStorageState.String())),
		})

		healthyWorkers := FilterWorkersByLocalStorageState(workers)
		assert.Equal(t, 3, len(healthyWorkers))
	})
}

func Test_FilterStorageBucketCredentialByWriteAccess(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		sbcState       *plugin.StorageBucketCredentialState
		expectedFilter bool
	}{
		{
			name:           "nil sbcState",
			expectedFilter: true,
		},
		{
			name:           "nil underlying state",
			sbcState:       &plugin.StorageBucketCredentialState{},
			expectedFilter: true,
		},
		{
			name: "nil write permission",
			sbcState: &plugin.StorageBucketCredentialState{
				State: &plugin.Permissions{},
			},
			expectedFilter: true,
		},
		{
			name: "ok state",
			sbcState: &plugin.StorageBucketCredentialState{
				State: &plugin.Permissions{
					Write: &plugin.Permission{
						State: plugin.StateType_STATE_TYPE_OK,
					},
				},
			},
			expectedFilter: true,
		},
		{
			name: "unknown state",
			sbcState: &plugin.StorageBucketCredentialState{
				State: &plugin.Permissions{
					Write: &plugin.Permission{
						State: plugin.StateType_STATE_TYPE_UNKNOWN,
					},
				},
			},
			expectedFilter: true,
		},
		{
			name: "error state",
			sbcState: &plugin.StorageBucketCredentialState{
				State: &plugin.Permissions{
					Write: &plugin.Permission{
						State: plugin.StateType_STATE_TYPE_ERROR,
					},
				},
			},
			expectedFilter: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			assert.Equal(tc.expectedFilter, FilterStorageBucketCredentialByWriteAccess(tc.sbcState))
		})
	}
}

func Test_FilterStorageBucketCredentialByReadAccess(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		sbcState       *plugin.StorageBucketCredentialState
		expectedFilter bool
	}{
		{
			name:           "nil sbcState",
			expectedFilter: true,
		},
		{
			name:           "nil underlying state",
			sbcState:       &plugin.StorageBucketCredentialState{},
			expectedFilter: true,
		},
		{
			name: "nil read permission",
			sbcState: &plugin.StorageBucketCredentialState{
				State: &plugin.Permissions{},
			},
			expectedFilter: true,
		},
		{
			name: "ok state",
			sbcState: &plugin.StorageBucketCredentialState{
				State: &plugin.Permissions{
					Read: &plugin.Permission{
						State: plugin.StateType_STATE_TYPE_OK,
					},
				},
			},
			expectedFilter: true,
		},
		{
			name: "unknown state",
			sbcState: &plugin.StorageBucketCredentialState{
				State: &plugin.Permissions{
					Read: &plugin.Permission{
						State: plugin.StateType_STATE_TYPE_UNKNOWN,
					},
				},
			},
			expectedFilter: true,
		},
		{
			name: "error state",
			sbcState: &plugin.StorageBucketCredentialState{
				State: &plugin.Permissions{
					Read: &plugin.Permission{
						State: plugin.StateType_STATE_TYPE_ERROR,
					},
				},
			},
			expectedFilter: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			assert.Equal(tc.expectedFilter, FilterStorageBucketCredentialByReadAccess(tc.sbcState))
		})
	}
}

func Test_FilterStorageBucketCredentialByDeleteAccess(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		sbcState       *plugin.StorageBucketCredentialState
		expectedFilter bool
	}{
		{
			name:           "nil sbcState",
			expectedFilter: true,
		},
		{
			name:           "nil underlying state",
			sbcState:       &plugin.StorageBucketCredentialState{},
			expectedFilter: true,
		},
		{
			name: "nil delete permission",
			sbcState: &plugin.StorageBucketCredentialState{
				State: &plugin.Permissions{},
			},
			expectedFilter: true,
		},
		{
			name: "ok state",
			sbcState: &plugin.StorageBucketCredentialState{
				State: &plugin.Permissions{
					Delete: &plugin.Permission{
						State: plugin.StateType_STATE_TYPE_OK,
					},
				},
			},
			expectedFilter: true,
		},
		{
			name: "unknown state",
			sbcState: &plugin.StorageBucketCredentialState{
				State: &plugin.Permissions{
					Delete: &plugin.Permission{
						State: plugin.StateType_STATE_TYPE_UNKNOWN,
					},
				},
			},
			expectedFilter: true,
		},
		{
			name: "error state",
			sbcState: &plugin.StorageBucketCredentialState{
				State: &plugin.Permissions{
					Delete: &plugin.Permission{
						State: plugin.StateType_STATE_TYPE_ERROR,
					},
				},
			},
			expectedFilter: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			assert.Equal(tc.expectedFilter, FilterStorageBucketCredentialByDeleteAccess(tc.sbcState))
		})
	}
}

func TestShuffle(t *testing.T) {
	t.Parallel()

	t.Run("noElements", func(t *testing.T) {
		in := WorkerList{}
		out, err := in.Shuffle()
		require.NoError(t, err)
		require.Equal(t, in, out)
	})

	t.Run("oneElement", func(t *testing.T) {
		in := WorkerList{NewWorker("test_scope", WithName("1"))}
		out, err := in.Shuffle()
		require.NoError(t, err)
		require.Equal(t, in, out)
	})

	t.Run("multipleElements", func(t *testing.T) {
		// We need a large amount of minimum workers here to statistically
		// mitigate against the case where Shuffle just-so-happens to shuffle
		// the elements into the same order they were in before.
		n := rand.IntN(1000-99) + 100 // [100, 1000]

		inOrder := make([]int, 0, n)
		in := make(WorkerList, 0, n)
		for i := 0; i < n; i++ {
			inOrder = append(inOrder, i)
			in = append(in, NewWorker("test", WithName(strconv.Itoa(i))))
		}

		out, err := in.Shuffle()
		require.NoError(t, err)
		require.ElementsMatch(t, in, out)

		outOrder := make([]int, 0)
		for _, w := range out {
			i, _ := strconv.Atoi(w.Name)
			outOrder = append(outOrder, i)
		}
		require.NotEqual(t, inOrder, outOrder)
	})
}
