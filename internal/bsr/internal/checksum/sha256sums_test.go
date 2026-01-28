// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package checksum_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/checksum"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	_ storage.Writer = (*testFile)(nil)
	_ hash.Hash      = (*testHash)(nil)
)

type testFile struct {
	b      strings.Builder
	closed bool

	withWrittenBytes int
	withWriteError   error
}

func (t *testFile) Write(b []byte) (int, error) {
	if t.withWriteError != nil || t.withWrittenBytes > 0 {
		return t.withWrittenBytes, t.withWriteError
	}
	return t.b.Write(b)
}

func (t *testFile) WriteString(s string) (int, error) {
	if t.withWriteError != nil || t.withWrittenBytes > 0 {
		return t.withWrittenBytes, t.withWriteError
	}
	return t.b.WriteString(s)
}

func (t *testFile) WriteAndClose(b []byte) (int, error) {
	if t.withWriteError != nil || t.withWrittenBytes > 0 {
		return t.withWrittenBytes, t.withWriteError
	}
	t.closed = true
	return t.b.Write(b)
}

func (t *testFile) Close() error {
	t.closed = true
	return nil
}

type testHash struct {
	withWrittenBytes int
	withWriteError   error
}

func (t *testHash) Write(b []byte) (int, error) {
	return t.withWrittenBytes, t.withWriteError
}

func (t *testHash) Sum(b []byte) []byte {
	return nil
}

func (t *testHash) Reset() {}

func (t *testHash) Size() int {
	return 0
}

func (t *testHash) BlockSize() int {
	return 0
}

func Test_NewSha256SumWriter(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		writer      storage.Writer
		hash        hash.Hash
		expectedErr string
	}{
		{
			name:        "missing writer",
			expectedErr: "checksum.NewSha256SumWriter: missing writer: invalid parameter",
		},
		{
			name:        "missing hash",
			writer:      &testFile{},
			expectedErr: "checksum.NewSha256SumWriter: missing hash: invalid parameter",
		},
		{
			name:   "success",
			writer: &testFile{},
			hash:   sha256.New(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w, err := checksum.NewSha256SumWriter(context.Background(), tc.writer, tc.hash)
			if tc.expectedErr != "" {
				require.Error(err)
				assert.Nil(w)
				assert.ErrorContains(err, tc.expectedErr)
				return
			}
			require.NoError(err)
			assert.NotNil(w)
		})
	}
}

func TestSha256SumWriter_Write(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		writer      *checksum.Sha256SumWriter
		expectedErr string
		data        []byte
	}{
		{
			name: "with-hash-error",
			writer: func() *checksum.Sha256SumWriter {
				writer, err := checksum.NewSha256SumWriter(context.Background(), &testFile{}, &testHash{
					withWriteError: fmt.Errorf("failed hash write"),
				})
				require.NoError(t, err)
				return writer
			}(),
			data:        []byte{},
			expectedErr: "failed hash write",
		},
		{
			name: "with-file-error",
			writer: func() *checksum.Sha256SumWriter {
				writer, err := checksum.NewSha256SumWriter(context.Background(), &testFile{
					withWriteError: fmt.Errorf("failed file write"),
				}, &testHash{
					withWrittenBytes: 10,
				})
				require.NoError(t, err)
				return writer
			}(),
			data:        []byte{},
			expectedErr: "failed file write",
		},
		{
			name: "with-short-write-error",
			writer: func() *checksum.Sha256SumWriter {
				writer, err := checksum.NewSha256SumWriter(context.Background(), &testFile{
					withWrittenBytes: 9,
				}, &testHash{
					withWrittenBytes: 10,
				})
				require.NoError(t, err)
				return writer
			}(),
			data:        []byte{},
			expectedErr: "short write",
		},
		{
			name: "success",
			writer: func() *checksum.Sha256SumWriter {
				writer, err := checksum.NewSha256SumWriter(context.Background(), &testFile{}, sha256.New())
				require.NoError(t, err)
				return writer
			}(),
			data: []byte("hello_world"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, err := tc.writer.Write(tc.data)
			if tc.expectedErr != "" {
				require.Error(err)
				assert.ErrorContains(err, tc.expectedErr)
				return
			}
			require.NoError(err)
		})
	}
}

func TestSha256SumWriter_WriteString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		writer      *checksum.Sha256SumWriter
		expectedErr string
	}{
		{
			name: "with-hash-error",
			writer: func() *checksum.Sha256SumWriter {
				writer, err := checksum.NewSha256SumWriter(context.Background(), &testFile{}, &testHash{
					withWriteError: fmt.Errorf("failed hash write"),
				})
				require.NoError(t, err)
				return writer
			}(),
			expectedErr: "failed hash write",
		},
		{
			name: "with-file-error",
			writer: func() *checksum.Sha256SumWriter {
				writer, err := checksum.NewSha256SumWriter(context.Background(), &testFile{
					withWriteError: fmt.Errorf("failed file write"),
				}, &testHash{
					withWrittenBytes: 10,
				})
				require.NoError(t, err)
				return writer
			}(),
			expectedErr: "failed file write",
		},
		{
			name: "with-short-write-error",
			writer: func() *checksum.Sha256SumWriter {
				writer, err := checksum.NewSha256SumWriter(context.Background(), &testFile{
					withWrittenBytes: 9,
				}, &testHash{
					withWrittenBytes: 10,
				})
				require.NoError(t, err)
				return writer
			}(),
			expectedErr: "short write",
		},
		{
			name: "success",
			writer: func() *checksum.Sha256SumWriter {
				writer, err := checksum.NewSha256SumWriter(context.Background(), &testFile{
					withWrittenBytes: 10,
				}, &testHash{
					withWrittenBytes: 10,
				})
				require.NoError(t, err)
				return writer
			}(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, err := tc.writer.WriteString("")
			if tc.expectedErr != "" {
				require.Error(err)
				assert.ErrorContains(err, tc.expectedErr)
				return
			}
			require.NoError(err)
		})
	}
}

func TestSha256SumWriter_WriteAndClose(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		writer      *checksum.Sha256SumWriter
		expectedErr string
	}{
		{
			name: "with-hash-error",
			writer: func() *checksum.Sha256SumWriter {
				writer, err := checksum.NewSha256SumWriter(context.Background(), &testFile{}, &testHash{
					withWriteError: fmt.Errorf("failed hash write"),
				})
				require.NoError(t, err)
				return writer
			}(),
			expectedErr: "failed hash write",
		},
		{
			name: "with-file-error",
			writer: func() *checksum.Sha256SumWriter {
				writer, err := checksum.NewSha256SumWriter(context.Background(), &testFile{
					withWriteError: fmt.Errorf("failed file write"),
				}, &testHash{
					withWrittenBytes: 10,
				})
				require.NoError(t, err)
				return writer
			}(),
			expectedErr: "failed file write",
		},
		{
			name: "with-short-write-error",
			writer: func() *checksum.Sha256SumWriter {
				writer, err := checksum.NewSha256SumWriter(context.Background(), &testFile{
					withWrittenBytes: 9,
				}, &testHash{
					withWrittenBytes: 10,
				})
				require.NoError(t, err)
				return writer
			}(),
			expectedErr: "short write",
		},
		{
			name: "success",
			writer: func() *checksum.Sha256SumWriter {
				writer, err := checksum.NewSha256SumWriter(context.Background(), &testFile{
					withWrittenBytes: 10,
				}, &testHash{
					withWrittenBytes: 10,
				})
				require.NoError(t, err)
				return writer
			}(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, err := tc.writer.WriteAndClose([]byte{})
			if tc.expectedErr != "" {
				require.Error(err)
				assert.ErrorContains(err, tc.expectedErr)
				return
			}
			require.NoError(err)
		})
	}
}

func TestSha256SumWriter_Sum(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testBytes := []byte("test-bytes")
	tests := []struct {
		name            string
		data            []byte
		sumWriter       *checksum.Sha256SumWriter
		opt             []checksum.Option
		wantSum         []byte
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "success",
			data: testBytes,
			sumWriter: func() *checksum.Sha256SumWriter {
				w, err := checksum.NewSha256SumWriter(testCtx, &testFile{}, sha256.New())
				require.NoError(t, err)
				return w
			}(),
			wantSum: func() []byte {
				hasher := sha256.New()
				_, err := hasher.Write(testBytes)
				require.NoError(t, err)
				_, err = hasher.Write(testBytes)
				require.NoError(t, err)
				return hasher.Sum(nil)
			}(),
		},
		{
			name: "success-with-hex-encoding",
			data: testBytes,
			sumWriter: func() *checksum.Sha256SumWriter {
				w, err := checksum.NewSha256SumWriter(testCtx, &testFile{}, sha256.New())
				require.NoError(t, err)
				return w
			}(),
			opt: []checksum.Option{checksum.WithHexEncoding(true)},
			wantSum: func() []byte {
				hasher := sha256.New()
				_, err := hasher.Write(testBytes)
				require.NoError(t, err)
				_, err = hasher.Write(testBytes)
				require.NoError(t, err)
				h := hasher.Sum(nil)
				return []byte(hex.EncodeToString(h[:]))
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, err := tc.sumWriter.Write(tc.data)
			require.NoError(err)
			_, err = tc.sumWriter.WriteString(string(tc.data))
			require.NoError(err)
			sum, err := tc.sumWriter.Sum(testCtx, tc.opt...)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(sum)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.wantSum, sum)
			require.NoError(tc.sumWriter.Close())
		})
	}

	t.Run("success-with-closer", func(t *testing.T) {
		c := testFile{
			b:      strings.Builder{},
			closed: false,
		}
		w, err := checksum.NewSha256SumWriter(testCtx, &c, sha256.New())
		require.NoError(t, err)

		hasher := sha256.New()
		_, err = hasher.Write(testBytes)
		require.NoError(t, err)
		_, err = hasher.Write(testBytes)
		require.NoError(t, err)
		wantSum := hasher.Sum(nil)

		assert, require := assert.New(t), require.New(t)
		_, err = w.Write(testBytes)
		require.NoError(err)
		_, err = w.WriteString(string(testBytes))
		require.NoError(err)
		sum, err := w.Sum(testCtx)
		require.NoError(err)
		assert.Equal(wantSum, sum)
		require.NoError(w.Close())

		require.True(c.closed)
	})
}

func TestLoadSha256Sums(t *testing.T) {
	cases := []struct {
		name    string
		r       io.Reader
		want    checksum.Sha256Sums
		wantErr error
	}{
		{
			"valid-multi-line-text",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e  file1
7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53  file2
`),
			checksum.Sha256Sums{
				"file1": []byte("ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e"),
				"file2": []byte("7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53"),
			},
			nil,
		},
		{
			"valid-multi-line-binary",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e *file1
7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53 *file2
`),
			checksum.Sha256Sums{
				"file1": []byte("ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e"),
				"file2": []byte("7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53"),
			},
			nil,
		},
		{
			"valid-multi-line-text-and-binary",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e  file1
7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53 *file2
`),
			checksum.Sha256Sums{
				"file1": []byte("ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e"),
				"file2": []byte("7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53"),
			},
			nil,
		},
		{
			"valid-multi-line-binary-and-text",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e *file1
7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53  file2
`),
			checksum.Sha256Sums{
				"file1": []byte("ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e"),
				"file2": []byte("7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53"),
			},
			nil,
		},
		{
			"invalid-single-space",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e file1`),
			nil,
			fmt.Errorf("checksum.LoadSha256Sums: improperly formated line"),
		},
		{
			"invalid-no-file",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e`),
			nil,
			fmt.Errorf("checksum.LoadSha256Sums: improperly formated line"),
		},
		{
			"invalid-no-sum-file",
			strings.NewReader(`file1`),
			nil,
			fmt.Errorf("checksum.LoadSha256Sums: improperly formated line"),
		},
		{
			"invalid-hash-too-short",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00  file1`),
			nil,
			fmt.Errorf("checksum.LoadSha256Sums: improperly formated line"),
		},
		{
			"invalid-hash-too-long",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00ef  file1`),
			nil,
			fmt.Errorf("checksum.LoadSha256Sums: improperly formated line"),
		},
		{
			"invalid-duplicate-file-name",
			strings.NewReader(`ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e  file1
7849ccae8fa91bb281a118041abf921636e68853059329ac68fccd8d518cea53  file1
`),
			nil,
			fmt.Errorf("checksum.LoadSha256Sums: duplicate file"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checksum.LoadSha256Sums(tc.r)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
