// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package convert

import (
	"context"
	"io"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/storage"
)

// ToAsciinema accepts a bsr.Session and will convert the underlying BSR connection or channel file to an asciinema file.
// The tempFs will be used to write the asciinema file to disk
// It returns an io.Reader to the converted asciinema file
// Supports WithChannelId() to indicate this conversion should occur on a chanel on a multiplexed session
func ToAsciinema(ctx context.Context, session bsr.Session, tempFs storage.FS, connectionId string, options ...Option) (io.Reader, error) {
	panic("not implemented")
}
