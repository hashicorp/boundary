// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbw

import (
	"context"
	"fmt"
	"time"
)

// DoTx will wrap the Handler func passed within a transaction with retries
// you should ensure that any objects written to the db in your TxHandler are retryable, which
// means that the object may be sent to the db several times (retried), so
// things like the primary key may need to be reset before retry.
func (rw *RW) DoTx(ctx context.Context, retryErrorsMatchingFn func(error) bool, retries uint, backOff Backoff, handler TxHandler) (RetryInfo, error) {
	const op = "dbw.DoTx"
	if rw.underlying == nil {
		return RetryInfo{}, fmt.Errorf("%s: missing underlying db: %w", op, ErrInvalidParameter)
	}
	if backOff == nil {
		return RetryInfo{}, fmt.Errorf("%s: missing backoff: %w", op, ErrInvalidParameter)
	}
	if handler == nil {
		return RetryInfo{}, fmt.Errorf("%s: missing handler: %w", op, ErrInvalidParameter)
	}
	if retryErrorsMatchingFn == nil {
		return RetryInfo{}, fmt.Errorf("%s: missing retry errors matching function: %w", op, ErrInvalidParameter)
	}
	info := RetryInfo{}
	for attempts := uint(1); ; attempts++ {
		if attempts > retries+1 {
			return info, fmt.Errorf("%s: too many retries: %d of %d: %w", op, attempts-1, retries+1, ErrMaxRetries)
		}

		// step one of this, start a transaction...
		newTx := rw.underlying.wrapped.WithContext(ctx)
		newTx = newTx.Begin()

		newRW := &RW{underlying: &DB{newTx}}
		if err := handler(newRW, newRW); err != nil {
			if err := newTx.Rollback().Error; err != nil {
				return info, fmt.Errorf("%s: %w", op, err)
			}
			if retry := retryErrorsMatchingFn(err); retry {
				d := backOff.Duration(attempts)
				info.Retries++
				info.Backoff = info.Backoff + d
				select {
				case <-ctx.Done():
					return info, fmt.Errorf("%s: cancelled: %w", op, err)
				case <-time.After(d):
					continue
				}
			}
			return info, fmt.Errorf("%s: %w", op, err)
		}

		if err := newTx.Commit().Error; err != nil {
			if err := newTx.Rollback().Error; err != nil {
				return info, fmt.Errorf("%s: %w", op, err)
			}
			return info, fmt.Errorf("%s: %w", op, err)
		}
		return info, nil // it all worked!!!
	}
}
