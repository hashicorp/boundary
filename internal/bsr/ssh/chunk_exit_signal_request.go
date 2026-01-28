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

const ExitSignalRequestType = "exit-signal"

// ExitSignalRequest is a chunk to contain data for an SSH Exit Signal request
type ExitSignalRequest struct {
	*bsr.BaseChunk
	*pssh.ExitSignalRequest
}

// MarshalData serializes an ExitSignalRequest chunk
func (r *ExitSignalRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(ExitSignalRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.ExitSignalRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewExitSignalRequest creates an ExitSignalRequest chunk
func NewExitSignalRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*ExitSignalRequest, error) {
	const op = "ssh.NewExitSignalRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != ExitSignalRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, ExitSignalRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, ExitSignalReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval exitSignalSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &ExitSignalRequest{
		BaseChunk: baseChunk,
		ExitSignalRequest: &pssh.ExitSignalRequest{
			RequestType:  r.Type,
			WantReply:    r.WantReply,
			SignalName:   sigval.SignalName,
			CoreDumped:   sigval.CoreDumped,
			ErrorMessage: sigval.ErrorMessage,
			LanguageTag:  sigval.LanguageTag,
		},
	}
	return reqData, nil
}

type exitSignalSigval struct {
	SignalName   string
	CoreDumped   bool
	ErrorMessage string
	LanguageTag  string
}
