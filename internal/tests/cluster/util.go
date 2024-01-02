// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package cluster

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func expectWorkers(t *testing.T, c *controller.TestController, workers ...*worker.TestWorker) {
	updateTimes := c.Controller().WorkerStatusUpdateTimes()
	workerMap := map[string]*worker.TestWorker{}
	for _, w := range workers {
		workerMap[w.Name()] = w
	}
	updateTimes.Range(func(k, v any) bool {
		require.NotNil(t, k)
		require.NotNil(t, v)
		if workerMap[k.(string)] == nil {
			// We don't remove from updateTimes currently so if we're not
			// expecting it we'll see an out-of-date entry
			return true
		}
		assert.WithinDuration(t, time.Now(), v.(time.Time), 30*time.Second)
		delete(workerMap, k.(string))
		return true
	})
	assert.Empty(t, workerMap)
}
