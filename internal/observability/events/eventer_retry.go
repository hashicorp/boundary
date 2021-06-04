package event

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-multierror"
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
		return errors.New(errors.InvalidParameter, op, "missing backoff")
	}
	if handler == nil {
		return errors.New(errors.InvalidParameter, op, "missing handler")
	}
	success := false
	var retryErrors error
	var attemptStatus eventlogger.Status
	info := retryInfo{}
	for attempts := uint(1); ; attempts++ {
		if attempts > retries+1 {
			retryErrors = multierror.Append(retryErrors, errors.New(errors.MaxRetries, op, fmt.Sprintf("Too many retries: reached max of %d", retries)))
			return retryErrors
		}
		var err error
		attemptStatus, err = handler()
		if len(attemptStatus.Warnings) > 0 {
			var retryWarnings error
			for _, w := range attemptStatus.Warnings {
				retryWarnings = multierror.Append(retryWarnings, w)
			}
			e.logger.Error("unable to send event", "operation", op, "warning", retryWarnings)
		}
		if err != nil {
			retryErrors = multierror.Append(retryErrors, errors.Wrap(err, op))
			d := backOff.duration(attempts)
			info.retries++
			info.backoff = info.backoff + d
			time.Sleep(d)
			continue
		}
		success = true
		break
	}
	if !success {
		return errors.Wrap(retryErrors, op, errors.WithMsg("failed to send event"))
	}
	return nil
}
