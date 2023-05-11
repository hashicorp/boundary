// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package convert

import (
	"context"
	"io"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/storage"
)

// ToAsciicast accepts a bsr.Session and will convert the underlying BSR connection or channel file to an asciinema file.
// The tempFs will be used to write the asciinema file to disk
// It returns an io.Reader to the converted asciinema file
// Supports WithChannelId() to indicate this conversion should occur on a chanel on a multiplexed session
func ToAsciicast(ctx context.Context, session bsr.Session, tmp storage.TempFile, connectionId string, options ...Option) (io.ReadCloser, error) {
	panic("not implemented")
}
