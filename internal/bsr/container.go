// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/bsr/internal/checksum"
	"github.com/hashicorp/boundary/internal/bsr/internal/journal"
	"github.com/hashicorp/boundary/internal/bsr/internal/sign"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/storage"
)

const (
	metaFile     = "%s.meta"
	summaryFile  = "%s.summary"
	checksumFile = "SHA256SUM"
	sigFile      = "SHA256SUM.sig"
	journalFile  = ".journal"
)

// ContainerType defines the type of container.
type containerType string

// Valid container types.
const (
	sessionContainer    containerType = "session"
	connectionContainer containerType = "connection"
	channelContainer    containerType = "channel"
)

// container contains a group of files in a BSR.
// Each container has corresponding .meta, .summary, SHA256SUM, and SHA256SUM.sig files.
type container struct {
	container storage.Container
	journal   *journal.Journal

	metaName  string
	sumName   string
	meta      *checksum.File
	sum       *checksum.File
	checksums *sign.File
	sigs      storage.File

	keys *kms.Keys
}

// newContainer creates a container for the given type backed by the provide storage.Container.
func newContainer(ctx context.Context, t containerType, c storage.Container, keys *kms.Keys) (*container, error) {
	j, err := c.OpenFile(ctx, journalFile,
		storage.WithCreateFile(),
		storage.WithFileAccessMode(storage.WriteOnly),
		storage.WithCloseSyncMode(storage.NoSync))
	if err != nil {
		return nil, err
	}
	jj, err := journal.New(ctx, j)
	if err != nil {
		return nil, err
	}
	cc := &container{
		container: c,
		journal:   jj,
		keys:      keys,
	}

	cc.sigs, err = cc.create(ctx, sigFile)
	if err != nil {
		return nil, err
	}

	cs, err := cc.create(ctx, checksumFile)
	if err != nil {
		return nil, err
	}
	cc.checksums, err = sign.NewFile(ctx, cs, cc.sigs, keys)
	if err != nil {
		return nil, err
	}

	cc.metaName = fmt.Sprintf(metaFile, t)
	meta, err := cc.create(ctx, cc.metaName)
	if err != nil {
		return nil, err
	}
	cc.meta, err = checksum.NewFile(ctx, meta, cc.checksums)
	if err != nil {
		return nil, err
	}

	cc.sumName = fmt.Sprintf(summaryFile, t)
	sum, err := cc.create(ctx, cc.sumName)
	if err != nil {
		return nil, err
	}
	cc.sum, err = checksum.NewFile(ctx, sum, cc.checksums)
	if err != nil {
		return nil, err
	}

	return cc, nil
}

// Create creates a new file in the container for writing.
func (c *container) create(ctx context.Context, s string) (storage.File, error) {
	c.journal.Record("CREATING", s)
	f, err := c.container.Create(ctx, s)
	if err != nil {
		return nil, err
	}
	jf, err := journal.NewFile(ctx, f, c.journal)
	if err != nil {
		return nil, err
	}
	defer c.journal.Record("CREATED", s)
	return jf, nil
}

// writeMetaString writes a string to the containers meta file.
func (c *container) writeMetaString(_ context.Context, s string) (int, error) {
	return c.meta.WriteString(s)
}

// writeMetaLine writes a new line terminated line to the container's meta file.
func (c *container) writeMetaLine(_ context.Context, s string) (int, error) {
	return c.meta.WriteString(s + "\n")
}

// WriteMeta writes a new line terminated key : value pair to the container's meta file
func (c *container) WriteMeta(_ context.Context, k, v string) (int, error) {
	return c.meta.WriteString(fmt.Sprintf("%s: %s\n", k, v))
}

// writeSummaryString writes a string to the container's summary file.
func (c *container) writeSummaryString(_ context.Context, s string) (int, error) {
	return c.sum.WriteString(s)
}

// WriteSummary writes a new line terminated key : value pair to the container's summary file
func (c *container) WriteSummary(_ context.Context, k, v string) (int, error) {
	return c.sum.WriteString(fmt.Sprintf("%s: %s\n", k, v))
}

// WriteSummaryLine writes a new line terminated string to the container's summary file.
func (c *container) WriteSummaryLine(_ context.Context, s string) (int, error) {
	return c.sum.WriteString(s + "\n")
}

// WriteBinaryChecksum writes a checksum for a binary file to the checksum file.
func (c *container) WriteBinaryChecksum(_ context.Context, sum []byte, fname string) (int, error) {
	return c.checksums.WriteString(fmt.Sprintf("%x *%s\n", sum, fname))
}

// close closes a container, closing the underlying files in a container.
func (c *container) close(_ context.Context) error {
	const op = "bsr.(container).close"

	var closeError error

	if err := c.meta.Close(); err != nil {
		closeError = errors.Join(closeError, fmt.Errorf("%s: %w", op, err))
	}

	if err := c.sum.Close(); err != nil {
		closeError = errors.Join(closeError, fmt.Errorf("%s: %w", op, err))
	}

	if err := c.checksums.Close(); err != nil {
		closeError = errors.Join(closeError, fmt.Errorf("%s: %w", op, err))
	}

	if err := c.sigs.Close(); err != nil {
		closeError = errors.Join(closeError, fmt.Errorf("%s: %w", op, err))
	}

	if err := c.journal.Close(); err != nil {
		closeError = errors.Join(closeError, fmt.Errorf("%s: %w", op, err))
	}

	if err := c.container.Close(); err != nil {
		closeError = errors.Join(closeError, fmt.Errorf("%s: %w", op, err))
	}

	return closeError
}
