// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/bsr"
	pssh "github.com/hashicorp/boundary/internal/bsr/gen/ssh/v1"
	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	gssh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// UnknownRequest is a chunk to contain data for any unrecognized SSH request
type UnknownRequest struct {
	*bsr.BaseChunk
	*pssh.UnknownRequest
}

// MarshalData serializes an UnknownRequest chunk
func (r *UnknownRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(UnknownRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.UnknownRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewUnknownRequest creates an UnknownRequest chunk
func NewUnknownRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*UnknownRequest, error) {
	const op = "ssh.NewUnknownRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, UnknownReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	return &UnknownRequest{
		BaseChunk: baseChunk,
		UnknownRequest: &pssh.UnknownRequest{
			RequestType: r.Type,
			WantReply:   r.WantReply,
			Data:        r.Payload,
		},
	}, nil
}
