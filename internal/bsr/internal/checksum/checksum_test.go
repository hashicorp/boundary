// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package checksum_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/checksum"
	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
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

	// testSum created via: echo -n "test-string" | sha256sum
	const (
		testSum    = "ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e"
		testString = "test-string"
	)

	cases := []struct {
		name                string
		f                   *fstest.MemFile
		cs                  bufWriter
		write               string
		want                string
		wantNewErr          error
		wantCloseErr        error
		expectCheckSumOnErr bool
	}{
		{
			"success",
			fstest.NewWritableMemFile("test"),
			bytes.NewBuffer([]byte{}),
			testString,
			testSum + "  test\n",
			nil,
			nil,
			false,
		},
		{
			"nil-file",
			nil,
			bytes.NewBuffer([]byte{}),
			testString,
			testSum + "  test\n",
			errors.New("checksum.NewFile: missing writable file: invalid parameter"),
			nil,
			false,
		},
		{
			"nil-checksum-writer",
			fstest.NewWritableMemFile("test"),
			nil,
			testString,
			testSum + "  test\n",
			errors.New("checksum.NewFile: missing checksum writer: invalid parameter"),
			nil,
			false,
		},
		{
			"close-error",
			fstest.NewWritableMemFile("test", fstest.WithCloseFunc(func() error { return errors.New("close error") })),
			bytes.NewBuffer([]byte{}),
			testString,
			testSum + "  test\n",
			nil,
			errors.New("checksum.(File).Close: checksum.(Sha256SumWriter).Close: close error"),
			true,
		},
		{
			"stat-error",
			fstest.NewWritableMemFile("test", fstest.WithStatFunc(func() (fs.FileInfo, error) { return nil, errors.New("stat error") })),
			bytes.NewBuffer([]byte{}),
			testString,
			testSum + "  test\n",
			nil,
			errors.New("checksum.(File).Close: stat error"),
			false,
		},
		{
			"write-error",
			fstest.NewWritableMemFile("test"),
			&badWriter{},
			testString,
			testSum + "  test\n",
			nil,
			errors.New("checksum.(File).Close: write failed"),
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := checksum.NewFile(ctx, tc.f, tc.cs)
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

				if tc.expectCheckSumOnErr {
					require.Equal(t, tc.want, tc.cs.String())
				} else {
					require.Equal(t, "", tc.cs.String())
				}
				return
			}
			require.NoError(t, err)

			require.True(t, tc.f.Closed)
			require.Equal(t, tc.want, tc.cs.String())
		})
	}
}
