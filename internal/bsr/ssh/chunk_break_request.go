// Copyright (c) HashiCorp, Inc.
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

const BreakRequestType = "break"

// BreakRequest is a chunk to contain data for an SSH Break request
type BreakRequest struct {
	*bsr.BaseChunk
	*pssh.BreakRequest
}

// MarshalData serializes a BreakRequest chunk
func (r *BreakRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(BreakRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.BreakRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewBreakRequest creates a BreakRequest chunk
func NewBreakRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*BreakRequest, error) {
	const op = "ssh.NewBreakRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != BreakRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, BreakRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, BreakReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval breakSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &BreakRequest{
		BaseChunk: baseChunk,
		BreakRequest: &pssh.BreakRequest{
			RequestType:   r.Type,
			WantReply:     r.WantReply,
			BreakLengthMs: sigval.BreakLengthMs,
		},
	}
	return reqData, nil
}

type breakSigval struct {
	BreakLengthMs uint32
}
