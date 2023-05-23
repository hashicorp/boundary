// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package servers

import (
	"context"
	"reflect"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

// RegisterJobs registers the rotate roots job with the provided scheduler.
func RegisterJobs(ctx context.Context, scheduler *scheduler.Scheduler, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) error {
	const op = "server.(Jobs).RegisterJobs"

	if isNil(scheduler) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scheduler")
	}
	if isNil(r) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing reader")
	}
	if isNil(w) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	}
	if kms == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}

	rotateRootsJob, err := newRotateRootsJob(ctx, r, w, kms, opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err = scheduler.RegisterJob(ctx, rotateRootsJob); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

func isNil(i any) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}
