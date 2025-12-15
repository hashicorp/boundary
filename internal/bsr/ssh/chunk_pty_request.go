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

const PtyRequestType = "pty-req"

// PtyPRequest is a chunk to contain data for an SSH Pty request
type PtyRequest struct {
	*bsr.BaseChunk
	*pssh.PtyRequest
}

// MarshalData serializes an PtyRequest chunk
func (r *PtyRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(PtyRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.PtyRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewPtyRequest creates an PtyRequest chunk
func NewPtyRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*PtyRequest, error) {
	const op = "ssh.NewPtyRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != PtyRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, PtyRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, PtyReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval ptySigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &PtyRequest{
		BaseChunk: baseChunk,
		PtyRequest: &pssh.PtyRequest{
			RequestType:             r.Type,
			WantReply:               r.WantReply,
			TermEnvVar:              sigval.TermEnvVar,
			TerminalWidthCharacters: sigval.TerminalWidthCharacters,
			TerminalHeightRows:      sigval.TerminalHeightRows,
			TerminalWidthPixels:     sigval.TerminalWidthPixels,
			TerminalHeightPixels:    sigval.TerminalHeightPixels,
			EncodedTerminalMode:     sigval.EncodedTerminalMode,
		},
	}
	return reqData, nil
}

type ptySigval struct {
	TermEnvVar              string
	TerminalWidthCharacters uint32
	TerminalHeightRows      uint32
	TerminalWidthPixels     uint32
	TerminalHeightPixels    uint32
	EncodedTerminalMode     []byte
}
