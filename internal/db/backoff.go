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
	DurationMs time.Duration
}

func (b ConstBackoff) Duration(attempt uint) time.Duration {
	return time.Millisecond * time.Duration(b.DurationMs)
}

type ExpBackoff struct{}

func (b ExpBackoff) Duration(attempt uint) time.Duration {
	r := rand.Float64()
	return time.Millisecond * time.Duration(math.Exp2(float64(attempt))*5*(r+0.5))
}
