// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
)

func withOptError(ctx context.Context) Option {
	return func(o *options) error {
		return errors.New(ctx, errors.Unknown, "withOptErrors", "with opt error")
	}
}
