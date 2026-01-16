// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package journal_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/internal/journal"
	"github.com/stretchr/testify/require"
)

type bufWriter interface {
	io.Writer
	String() string
}

type badWriter struct{}

func (*badWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}

func (*badWriter) String() string {
	return ""
}

func TestFile(t *testing.T) {
	ctx := context.Background()

	const (
		testString = "test-string"
	)

	cases := []struct {
		name           string
		f              *fstest.MemFile
		buf            bufWriter
		newJournalFunc func(w bufWriter) *journal.Journal
		write          string
		want           string
		wantNewErr     error
		wantCloseErr   error
	}{
		{
			"success",
			fstest.NewWritableMemFile("test"),
			bytes.NewBuffer([]byte{}),
			func(w bufWriter) *journal.Journal { ww, err := journal.New(ctx, w); require.NoError(t, err); return ww },
			testString,
			"CLOSING test\nCLOSED test\n",
			nil,
			nil,
		},
		{
			"nil-file",
			nil,
			bytes.NewBuffer([]byte{}),
			func(w bufWriter) *journal.Journal { ww, err := journal.New(ctx, w); require.NoError(t, err); return ww },
			testString,
			"",
			errors.New("journal.NewFile: missing writable file: invalid parameter"),
			nil,
		},
		{
			"nil-journal-writer",
			fstest.NewWritableMemFile("test"),
			nil,
			func(w bufWriter) *journal.Journal { return nil },
			testString,
			"",
			errors.New("journal.NewFile: missing journal: invalid parameter"),
			nil,
		},
		{
			"close-error",
			fstest.NewWritableMemFile("test", fstest.WithCloseFunc(func() error { return errors.New("close error") })),
			bytes.NewBuffer([]byte{}),
			func(w bufWriter) *journal.Journal { ww, err := journal.New(ctx, w); require.NoError(t, err); return ww },
			testString,
			"CLOSING test\n",
			nil,
			errors.New("journal.(File).Close: close error"),
		},
		{
			"stat-error",
			fstest.NewWritableMemFile("test", fstest.WithStatFunc(func() (fs.FileInfo, error) { return nil, errors.New("stat error") })),
			bytes.NewBuffer([]byte{}),
			func(w bufWriter) *journal.Journal { ww, err := journal.New(ctx, w); require.NoError(t, err); return ww },
			testString,
			"",
			nil,
			errors.New("journal.(File).Close: stat error"),
		},
		{
			"write-error",
			fstest.NewWritableMemFile("test"),
			&badWriter{},
			func(w bufWriter) *journal.Journal { ww, err := journal.New(ctx, w); require.NoError(t, err); return ww },
			testString,
			"",
			nil,
			errors.New("journal.(File).Close: write failed"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := tc.newJournalFunc(tc.buf)

			f, err := journal.NewFile(ctx, tc.f, j)
			if tc.wantNewErr != nil {
				require.EqualError(t, tc.wantNewErr, err.Error())
				return
			}
			require.NoError(t, err)

			_, err = f.WriteString(tc.write)
			require.NoError(t, err)

			err = f.Close()
			if tc.wantCloseErr != nil {
				require.EqualError(t, err, tc.wantCloseErr.Error())

				require.Equal(t, tc.want, tc.buf.String())
				return
			}
			require.NoError(t, err)

			require.True(t, tc.f.Closed)
			require.Equal(t, tc.want, tc.buf.String())
		})
	}
}
