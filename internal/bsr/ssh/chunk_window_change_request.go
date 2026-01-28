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

const WindowChangeRequestType = "window-change"

// WindowChangeRequest is a chunk to contain data for an SSH Window Change request
type WindowChangeRequest struct {
	*bsr.BaseChunk
	*pssh.WindowChangeRequest
}

// MarshalData serializes an WindowChangeRequest chunk
func (r *WindowChangeRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(WindowChangeRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.WindowChangeRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewWindowChangeRequest creates a WindowChangeRequest chunk
func NewWindowChangeRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*WindowChangeRequest, error) {
	const op = "ssh.NewWindowChangeRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != WindowChangeRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, WindowChangeRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, WindowChangeReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval windowChangeSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &WindowChangeRequest{
		BaseChunk: baseChunk,
		WindowChangeRequest: &pssh.WindowChangeRequest{
			RequestType:          r.Type,
			WantReply:            r.WantReply,
			TerminalWidthColumns: sigval.TerminalWidthColumns,
			TerminalHeightRows:   sigval.TerminalHeightRows,
			TerminalWidthPixels:  sigval.TerminalWidthPixels,
			TerminalHeightPixels: sigval.TerminalHeightPixels,
		},
	}
	return reqData, nil
}

type windowChangeSigval struct {
	TerminalWidthColumns uint32
	TerminalHeightRows   uint32
	TerminalWidthPixels  uint32
	TerminalHeightPixels uint32
}
