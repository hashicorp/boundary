// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"math"
	"math/rand"
	"time"
)

type Backoff interface {
	Duration(attemptNumber uint) time.Duration
}

type ConstBackoff struct {
	Amount time.Duration
}

func (b ConstBackoff) Duration(attempt uint) time.Duration {
	return time.Millisecond * time.Duration(b.Amount)
}

type ExpBackoff struct{}

func (b ExpBackoff) Duration(attempt uint) time.Duration {
	r := rand.Float64()
	return time.Millisecond * time.Duration(math.Exp2(float64(attempt))*5*(r+0.5))
}
