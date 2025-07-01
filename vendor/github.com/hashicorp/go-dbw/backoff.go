// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbw

import (
	"math"
	"math/rand"
	"time"
)

// Backoff defines an interface for providing a back off for retrying
// transactions. See DoTx(...)
type Backoff interface {
	Duration(attemptNumber uint) time.Duration
}

// ConstBackoff defines a constant backoff for retrying transactions. See
// DoTx(...)
type ConstBackoff struct {
	DurationMs time.Duration
}

// Duration is the constant backoff duration based on the retry attempt
func (b ConstBackoff) Duration(attempt uint) time.Duration {
	return time.Millisecond * time.Duration(b.DurationMs)
}

// ExpBackoff defines an exponential backoff for retrying transactions. See DoTx(...)
type ExpBackoff struct {
	testRand float64
}

// Duration is the exponential backoff duration based on the retry attempt
func (b ExpBackoff) Duration(attempt uint) time.Duration {
	var r float64
	switch {
	case b.testRand > 0:
		r = b.testRand
	default:
		r = rand.Float64()
	}
	return time.Millisecond * time.Duration(math.Exp2(float64(attempt))*5*(r+0.5))
}
