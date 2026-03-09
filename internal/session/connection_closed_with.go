// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
)

// CloseWith defines the boundary data that is saved in the repo when the
// worker closes a connection between the client and the endpoint.
type CloseWith struct {
	ConnectionId string
	BytesUp      int64
	BytesDown    int64
	ClosedReason ClosedReason
}

func (c CloseWith) validate(ctx context.Context) error {
	const op = "session.(CloseWith).validate"
	if c.ConnectionId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing connection id")
	}
	if c.ClosedReason.String() == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing closed reason")
	}
	// 0 is valid for BytesUp and BytesDown
	return nil
}
