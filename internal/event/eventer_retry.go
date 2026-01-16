// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"context"
	stderrors "errors"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/hashicorp/eventlogger"
)

const (
	// stdRetryCount is the standard number of times for retry when sending events
	stdRetryCount = 3
)

type backoff interface {
	duration(attemptNumber uint) time.Duration
}

type expBackoff struct{}

// duration returns an exponential backing off time duration
func (b expBackoff) duration(attempt uint) time.Duration {
	r := rand.Float64()
	return time.Millisecond * time.Duration(math.Exp2(float64(attempt))*5*(r+0.5))
}

type retryInfo struct {
	retries int
	backoff time.Duration
}

type sendHandler func() (eventlogger.Status, error)

// retrySend will attempt sendHandler (which is intended to be a closure that
// sends an event) the specified number of retries using the specified backoff.
func (e *Eventer) retrySend(ctx context.Context, retries uint, backOff backoff, handler sendHandler) error {
	const op = "event.(Eventer).retrySend"
	if backOff == nil {
		return fmt.Errorf("%s: missing backoff: %w", op, ErrInvalidParameter)
	}
	if handler == nil {
		return fmt.Errorf("%s: missing handler: %w", op, ErrInvalidParameter)
	}
	success := false
	var retryErrors error
	var attemptStatus eventlogger.Status
	info := retryInfo{}
ATTEMPTS:
	for attempts := uint(1); ; attempts++ {
		if attempts > retries+1 {
			retryErrors = stderrors.Join(retryErrors, fmt.Errorf("%s: reached max of %d: %w", op, retries, ErrMaxRetries))
			return retryErrors
		}
		var err error
		attemptStatus, err = handler()
		if len(attemptStatus.Warnings) > 0 {
			var retryWarnings error
			for _, w := range attemptStatus.Warnings {
				retryWarnings = stderrors.Join(retryWarnings, w)
			}
			e.logger.Error("unable to send event", "operation", op, "warning", retryWarnings)
		}
		if err != nil {
			retryErrors = stderrors.Join(retryErrors, fmt.Errorf("%s: %w", op, err))
			d := backOff.duration(attempts)
			info.retries++
			info.backoff = info.backoff + d
			select {
			case <-ctx.Done():
				retryErrors = stderrors.Join(retryErrors, ctx.Err())
				break ATTEMPTS
			case <-time.After(d):
				continue
			}
		}
		success = true
		break
	}
	if !success {
		return fmt.Errorf("%s: failed to send event: %w", op, retryErrors)
	}
	return nil
}
