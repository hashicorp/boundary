// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package cache

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
	"golang.org/x/sys/windows"
)

func writePidFile(ctx context.Context, pidFile string) (pidCleanup, error) {
	const op = "cache.writePidFile"
	// Create the file for writing, and set shared read so following processes
	// cannot open this file for writing.
	fd, err := windows.CreateFile(&(windows.StringToUTF16(pidFile)[0]), windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return noopPidCleanup, errors.Wrap(ctx, err, op)
	}

	cleanup := func() error {
		var err error
		if inErr := windows.CloseHandle(fd); inErr != nil {
			err = stderrors.Join(err, errors.Wrap(ctx, inErr, op, errors.WithMsg("handler close")))
		}
		if inErr := windows.DeleteFile(&(windows.StringToUTF16(pidFile)[0])); inErr != nil {
			err = stderrors.Join(err, errors.Wrap(ctx, inErr, op, errors.WithMsg("removing file")))
		}
		return err
	}

	if _, err := windows.Seek(fd, 0, windows.FILE_BEGIN); err != nil {
		return cleanup, errors.Wrap(ctx, err, op)
	}
	b := bytes.NewBuffer(nil)
	if _, err := fmt.Fprint(b, os.Getpid()); err != nil {
		return cleanup, errors.Wrap(ctx, err, op, errors.WithMsg("writing file buffer"))
	}
	var fileLen int
	if fileLen, err = windows.Write(fd, b.Bytes()); err != nil {
		return cleanup, errors.Wrap(ctx, err, op, errors.WithMsg("writing buffer to file"))
	}
	if err = windows.Ftruncate(fd, int64(fileLen)); err != nil {
		return cleanup, errors.Wrap(ctx, err, op)
	}

	return cleanup, windows.Fsync(fd)
}

func pidFileInUse(ctx context.Context, pidFile string) (*os.Process, error) {
	const op = "cache.pidFileInUse"
	if pidFile == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "pid filename is empty")
	}

	var err error
	var file *os.File
	if file, err = os.OpenFile(pidFile, os.O_RDONLY, 0o640); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("OpenFile"))
	}
	if file == nil {
		return nil, nil
	}
	defer func() {
		file.Close()
	}()

	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var pid int
	_, err = fmt.Fscan(file, &pid)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Fscan"))
	}

	p, err := os.FindProcess(pid)
	if err != nil {
		if strings.Contains(err.Error(), "The parameter is incorrect") {
			return nil, errors.New(ctx, errors.NotFound, op, "cannot find process")
		}
		// we failed to get the process for whatever reason
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("FindProcess %d", pid))
	}
	if p == nil {
		return nil, errors.New(ctx, errors.NotFound, op, "cannot find process")
	}
	return p, nil
}
