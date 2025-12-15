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

const SignalRequestType = "signal"

// SignalRequest is a chunk to contain data for an SSH Signal request
type SignalRequest struct {
	*bsr.BaseChunk
	*pssh.SignalRequest
}

// MarshalData serializes an SignalRequest chunk
func (r *SignalRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(SignalRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.SignalRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewSignalRequest creates an SignalRequest chunk
func NewSignalRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*SignalRequest, error) {
	const op = "ssh.NewSignalRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != SignalRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, SignalRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, SignalReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval signalSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &SignalRequest{
		BaseChunk: baseChunk,
		SignalRequest: &pssh.SignalRequest{
			RequestType: r.Type,
			WantReply:   r.WantReply,
			SignalName:  sigval.SignalName,
		},
	}
	return reqData, nil
}

type signalSigval struct {
	SignalName string
}
