// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package batch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Parallel()
	t.Run("nil-config", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		got, err := New(ctx, nil)
		require.Error(t, err)
		assert.Nil(t, got)
	})
	t.Run("nil-Exec", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		config := &Config{}
		got, err := New(ctx, config)
		require.Error(t, err)
		assert.Nil(t, got)
	})
	t.Run("minimum-config", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		config := &Config{
			Exec: func(ctx context.Context, batchSize int) (int, error) { return 0, nil },
		}
		got, err := New(ctx, config)
		require.NoError(t, err)
		assert.NotNil(t, got)
	})
}

func TestConfig(t *testing.T) {
	t.Parallel()
	t.Run("default-config", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		config := &Config{
			Exec: func(ctx context.Context, batchSize int) (int, error) { return 0, nil },
		}
		assert.Equal(DefaultSize, config.size())
		assert.Equal(DefaultMin, config.min())
		assert.Equal(DefaultMax, config.max())
		assert.Equal(DefaultStatusThreshold-statusThresholdBuffer, config.statusThreshold())
		assert.Equal(DefaultTarget, config.target())
		config.StatusThreshold = DefaultTarget
		config.Target = DefaultTarget
		want := DefaultTarget - statusThresholdBuffer
		assert.Equal(want, config.target())
	})
	tests := []struct {
		min, max, size int
		want           int
	}{
		{0, 0, 0, DefaultSize},
		{0, 0, DefaultMin - 1, DefaultMin},
		{0, 0, DefaultMax + 1, DefaultMax},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("min-max-size_%d-%d-%d", tt.min, tt.max, tt.size), func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			config := &Config{
				Min:  tt.min,
				Max:  tt.max,
				Size: tt.size,
			}
			assert.Equal(tt.want, config.size())
		})
	}
}

type testStore struct {
	called    bool
	batchSize int
}

func (s *testStore) Store(ctx context.Context, batchSize int) error {
	s.called = true
	s.batchSize = batchSize
	return nil
}

func TestConfig_setSize(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	config := &Config{
		Min:  5,
		Max:  15,
		Size: 10,
	}
	tests := []struct {
		newSize    int
		wantSize   int
		wantCalled bool
	}{
		{0, 5, true},
		{4, 5, true},
		{5, 5, true},
		{6, 6, true},
		{10, 10, false},
		{20, 15, true},
		{15, 15, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("newSize_%d", tt.newSize), func(t *testing.T) {
			t.Parallel()
			assert, require := assert.New(t), require.New(t)
			c := config.clone()
			assert.Equal(config, c)

			ts := &testStore{}
			c.Store = ts.Store

			err := c.setSize(ctx, tt.newSize)
			require.NoError(err)
			assert.Equal(tt.wantSize, c.Size)
			assert.Equal(tt.wantCalled, ts.called)
			if tt.wantCalled {
				assert.Equal(tt.wantSize, ts.batchSize)
			}
		})
	}
}

func TestConfig_targetRange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		target    time.Duration
		wantUpper time.Duration
		wantLower time.Duration
	}{
		{
			target:    1000 * time.Millisecond,
			wantLower: 900 * time.Millisecond,
			wantUpper: 1100 * time.Millisecond,
		},
		{
			target:    60 * time.Second,
			wantLower: 54 * time.Second,
			wantUpper: 66 * time.Second,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("target_%d", tt.target), func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			config := &Config{
				Target: tt.target,
			}
			assert.Equal(tt.target, config.target())
			lower, upper := config.targetRange()
			assert.Equal(tt.wantLower, lower)
			assert.Equal(tt.wantUpper, upper)
		})
	}
}

func TestConfig_exponentialDecrease(t *testing.T) {
	t.Parallel()
	tests := []struct {
		batchSize int
		attempt   int
		expected  int
	}{
		{10, 0, DefaultMin},
		{10, 1, DefaultMin},
		{10, 2, DefaultMin},
		{9, 1, DefaultMin},
		{9, 2, DefaultMin},
		{1000, 0, 500},
		{1000, 1, 500},
		{1000, 2, 250},
		{1000, 3, 125},
		{1000, 4, 62},
		{1000, 5, 31},
		{1000, 6, 15},
		{1000, 7, DefaultMin},
		{500, 1, 250},
		{500, 2, 125},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("batchSize=%d/attempt=%d", tt.batchSize, tt.attempt), func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			c := &Config{
				Size: tt.batchSize,
			}
			delta := c.size() / 10
			err := c.exponentialDecrease(ctx, tt.attempt)
			require.NoError(err)
			assert.InDelta(tt.expected, c.Size, float64(delta))
		})
	}
}

func Test_linearDecrease(t *testing.T) {
	t.Parallel()
	tests := []struct {
		batchSize int
		attempt   int
		expected  int
	}{
		{10, 0, DefaultMin},
		{10, 1, DefaultMin},
		{10, 2, DefaultMin},
		{1000, 0, 900},
		{1000, 1, 900},
		{1000, 2, 800},
		{1000, 3, 700},
		{1000, 4, 600},
		{1000, 5, 500},
		{1000, 6, 400},
		{1000, 7, 300},
		{1000, 10, DefaultMin},
		{1000, 11, DefaultMin},
		{500, 1, 450},
		{500, 2, 400},
		{100, 1, 90},
		{100, 2, 80},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("batchSize=%d/attempt=%d", tt.batchSize, tt.attempt), func(t *testing.T) {
			t.Parallel()
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			c := &Config{
				Size: tt.batchSize,
			}
			delta := c.size() / 10
			err := c.linearDecrease(ctx, tt.attempt)
			require.NoError(err)
			assert.InDelta(tt.expected, c.Size, float64(delta))
		})
	}
}

func Test_linearIncrease(t *testing.T) {
	t.Parallel()
	tests := []struct {
		batchSize int
		attempt   int
		expected  int
	}{
		{10000, 0, DefaultMax},
		{10000, 1, DefaultMax},
		{10000, 2, DefaultMax},
		{1000, 0, 1100},
		{1000, 1, 1100},
		{1000, 2, 1200},
		{1000, 3, 1300},
		{1000, 4, 1400},
		{1000, 5, 1500},
		{1000, 6, 1600},
		{1000, 7, 1700},
		{500, 1, 550},
		{500, 2, 600},
		{100, 1, 110},
		{100, 2, 120},
		{10, 1, 11},
		{10, 2, 12},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("batchSize=%d/attempt=%d", tt.batchSize, tt.attempt), func(t *testing.T) {
			t.Parallel()
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			c := &Config{
				Size: tt.batchSize,
			}
			delta := c.size() / 10
			err := c.linearIncrease(ctx, tt.attempt)
			require.NoError(err)
			assert.InDelta(tt.expected, c.Size, float64(delta))
		})
	}
}

type recorder struct {
	execBatchSize  int
	storeBatchSize int
	status         scheduler.JobStatus
	mu             sync.Mutex
}

func (r *recorder) setup(c *Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c.Store = r.Store
}

func (r *recorder) Store(ctx context.Context, batchSize int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.storeBatchSize = batchSize
	return nil
}

func (r *recorder) Exec(ctx context.Context, batchSize int) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.execBatchSize = batchSize
	return 0, nil
}

type testRun struct {
	ret func(context.Context, int, *Config) (int, error)
	chk func(*testing.T, *recorder)
	rec *recorder
	mu  sync.Mutex
}

func (tr *testRun) validate(t *testing.T) {
	if tr.chk != nil {
		tr.chk(t, tr.rec)
	}
}

func (tr *testRun) recorder(cf *Config) *recorder {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.rec == nil {
		tr.rec = &recorder{}
		tr.rec.setup(cf)
	}
	return tr.rec
}

type testRunner struct {
	conf *Config
	b    *Batch
	runs []*testRun
	t    *testing.T
	call int
}

func newTestRunner(t *testing.T, conf *Config, b *Batch) *testRunner {
	tr := &testRunner{
		t:    t,
		conf: conf,
		b:    b,
	}
	conf.Exec = tr.Exec
	return tr
}

func (tr *testRunner) Exec(ctx context.Context, batchSize int) (int, error) {
	if tr.call > 0 {
		prevRun := tr.runs[tr.call-1]
		prevRun.rec.status = tr.b.Status()
		prevRun.validate(tr.t)
	}
	run := tr.runs[tr.call]
	rec := run.recorder(tr.conf)
	if _, err := rec.Exec(ctx, batchSize); err != nil {
		return 0, err
	}
	tr.call++
	return run.ret(ctx, batchSize, tr.conf)
}

func TestRun(t *testing.T) {
	const testStatusTotal = 10

	t.Parallel()
	assertStoreCalled := func() func(*testing.T, *recorder) {
		const op = "assertStoreCalled"
		return func(t *testing.T, r *recorder) {
			assert.Positive(t, r.storeBatchSize, op)
		}
	}
	assertStoreNotCalled := func() func(*testing.T, *recorder) {
		const op = "assertStoreNotCalled"
		return func(t *testing.T, r *recorder) {
			t.Helper()
			assert.Zero(t, r.storeBatchSize, op)
		}
	}
	assertRetryCalled := func() func(*testing.T, *recorder) {
		const op = "assertRetryCalled"
		return func(t *testing.T, r *recorder) {
			assert.Positive(t, r.status.Retries, op)
		}
	}
	assertRetryNotCalled := func() func(*testing.T, *recorder) {
		const op = "assertRetryNotCalled"
		return func(t *testing.T, r *recorder) {
			assert.Zero(t, r.status.Retries, op)
		}
	}
	assertCompletedCalled := func() func(*testing.T, *recorder) {
		const op = "assertCompletedCalled"
		return func(t *testing.T, r *recorder) {
			assert.Positive(t, r.status.Completed, op)
		}
	}
	assertCompletedNotCalled := func() func(*testing.T, *recorder) {
		const op = "assertCompletedNotCalled"
		return func(t *testing.T, r *recorder) {
			assert.Zero(t, r.status.Completed, op)
		}
	}
	assertStatusTotal := func() func(*testing.T, *recorder) {
		const op = "assertStatusTotal"
		return func(t *testing.T, r *recorder) {
			assert.Equal(t, testStatusTotal, r.status.Total, op)
		}
	}
	combine := func(fns ...func(*testing.T, *recorder)) func(*testing.T, *recorder) {
		return func(t *testing.T, r *recorder) {
			for _, fn := range fns {
				fn(t, r)
			}
		}
	}

	execLessThanBatch := func() func(context.Context, int, *Config) (int, error) {
		return func(ctx context.Context, batchSize int, c *Config) (int, error) {
			return batchSize - 1, nil
		}
	}
	execTimeout := func() func(context.Context, int, *Config) (int, error) {
		return func(ctx context.Context, batchSize int, c *Config) (int, error) {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
	}
	execError := func() func(context.Context, int, *Config) (int, error) {
		return func(ctx context.Context, batchSize int, c *Config) (int, error) {
			return 0, errors.New("fake error")
		}
	}
	execSlow := func() func(context.Context, int, *Config) (int, error) {
		return func(ctx context.Context, batchSize int, c *Config) (int, error) {
			_, upper := c.targetRange()
			time.Sleep(upper + (2 * time.Millisecond))
			return batchSize, nil
		}
	}
	execTargetRange := func() func(context.Context, int, *Config) (int, error) {
		return func(ctx context.Context, batchSize int, c *Config) (int, error) {
			time.Sleep(c.Target)
			return batchSize, nil
		}
	}

	runMap := map[string]*testRun{
		"execLessThanBatch": {
			ret: execLessThanBatch(),
			chk: combine(assertStatusTotal(), assertStoreNotCalled(), assertRetryNotCalled(), assertCompletedCalled()),
		},
		"execTimeout": {
			ret: execTimeout(),
			chk: combine(assertStatusTotal(), assertStoreCalled(), assertRetryCalled(), assertCompletedNotCalled()),
		},
		"execError": {
			ret: execError(),
			chk: combine(assertStatusTotal(), assertStoreNotCalled(), assertRetryNotCalled(), assertCompletedNotCalled()),
		},
		"execSlow": {
			ret: execSlow(),
			chk: combine(assertStatusTotal(), assertStoreCalled(), assertRetryNotCalled(), assertCompletedCalled()),
		},
		"execTargetRange": {
			ret: execTargetRange(),
			chk: combine(assertStatusTotal(), assertStoreNotCalled(), assertRetryNotCalled(), assertCompletedCalled()),
		},
	}

	tests := []struct {
		name    string
		conf    *Config
		runs    []*testRun
		wantErr bool
	}{
		{
			name: "normal",
			conf: &Config{
				TotalToComplete: testStatusTotal,
			},
			runs: []*testRun{runMap["execLessThanBatch"]},
		},
		{
			name: "error",
			conf: &Config{
				TotalToComplete: testStatusTotal,
			},
			runs:    []*testRun{runMap["execError"]},
			wantErr: true,
		},
		{
			name: "timeout-normal",
			conf: &Config{
				TotalToComplete: testStatusTotal,
				StatusThreshold: 5 * time.Millisecond,
			},
			runs: []*testRun{runMap["execTimeout"], runMap["execLessThanBatch"]},
		},
		{
			name: "slow-normal",
			conf: &Config{
				TotalToComplete: testStatusTotal,
				StatusThreshold: 5 * time.Millisecond,
			},
			runs: []*testRun{runMap["execSlow"], runMap["execLessThanBatch"]},
		},
		{
			name: "target-normal",
			conf: &Config{
				TotalToComplete: testStatusTotal,
				Target:          1 * time.Second,
			},
			runs: []*testRun{runMap["execTargetRange"], runMap["execLessThanBatch"]},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			ctx := context.Background()
			b := &Batch{
				c: tt.conf,
			}
			tr := newTestRunner(t, tt.conf, b)
			tr.runs = tt.runs

			if err := b.Run(ctx); tt.wantErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}
		})
	}
}

func TestBatch_batchCompleted(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	config := &Config{
		Exec: func(ctx context.Context, batchSize int) (int, error) { return 0, nil },
		Store: func(ctx context.Context, batchSize int) error {
			fmt.Println("batchSize: ", batchSize)
			return nil
		},
	}
	b, err := New(ctx, config)
	require.NoError(err)
	assert.NotNil(b)

	err = b.adjustSize(ctx, 10)
	require.NoError(err)
}
