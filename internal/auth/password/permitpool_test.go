// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPermitPool(t *testing.T) {
	pool := newResizablePermitPool(1)
	wg := &sync.WaitGroup{}
	start := make(chan struct{})

	ctx := context.Background()
	// Start 5 goroutines all trying to acquire the permit at the same time
	for i := range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			t.Log("Goroutine " + strconv.Itoa(i) + " starting")
			err := pool.Do(ctx, func() {
				// Do some expensive operation
				time.Sleep(10 * time.Millisecond)
			})
			assert.NoError(t, err)
			t.Log("Goroutine " + strconv.Itoa(i) + " finished")
		}()
	}

	// Also start a few goroutines that attempt to resize the pool
	for i := range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			t.Log("Resizing pool " + strconv.Itoa(i))
			err := pool.SetPermits(2)
			t.Log("Resized pool" + strconv.Itoa(i))
			assert.NoError(t, err)
		}()
	}

	close(start)
	wg.Wait()
}
