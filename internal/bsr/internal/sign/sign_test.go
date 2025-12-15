// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sign_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/internal/sign"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type bufWriter interface {
	io.Writer
	Bytes() []byte
}

type badWriter struct{}

func (*badWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}

func (*badWriter) Bytes() []byte {
	return nil
}

func TestFile(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	testSig := []byte("")
	const (
		testString = "test-string"
	)

	cases := []struct {
		name               string
		f                  *fstest.MemFile
		sig                bufWriter
		keys               *kms.Keys
		write              string
		want               []byte
		wantNewErr         error
		wantCloseErr       error
		expectSigInfoOnErr bool
	}{
		{
			"success",
			fstest.NewWritableMemFile("test"),
			bytes.NewBuffer([]byte{}),
			keys,
			testString,
			testSig,
			nil,
			nil,
			false,
		},
		{
			"nil-file",
			nil,
			bytes.NewBuffer([]byte{}),
			keys,
			testString,
			testSig,
			errors.New("sign.NewFile: missing writable file: invalid parameter"),
			nil,
			false,
		},
		{
			"nil-sign-writer",
			fstest.NewWritableMemFile("test"),
			nil,
			keys,
			testString,
			testSig,
			errors.New("sign.NewFile: missing sign writer: invalid parameter"),
			nil,
			false,
		},
		{
			"nil-keys",
			fstest.NewWritableMemFile("test"),
			bytes.NewBuffer([]byte{}),
			nil,
			testString,
			testSig,
			errors.New("sign.NewFile: missing keys: invalid parameter"),
			nil,
			false,
		},
		{
			"close-error",
			fstest.NewWritableMemFile("test", fstest.WithCloseFunc(func() error { return errors.New("close error") })),
			bytes.NewBuffer([]byte{}),
			keys,
			testString,
			testSig,
			nil,
			errors.New("sign.(File).Close: sign.(Writer).Close: close error"),
			true,
		},
		{
			"write-error",
			fstest.NewWritableMemFile("test"),
			&badWriter{},
			keys,
			testString,
			testSig,
			nil,
			errors.New("sign.(File).Close: write failed"),
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := sign.NewFile(ctx, tc.f, tc.sig, tc.keys)
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

				if tc.expectSigInfoOnErr {
					sigInfo := &wrapping.SigInfo{}
					err = proto.Unmarshal(tc.sig.Bytes(), sigInfo)
					require.NoError(t, err)
					want, err := keys.SignWithPrivKey(ctx, []byte(tc.write))
					require.NoError(t, err)
					assert.Empty(t,
						cmp.Diff(
							want,
							sigInfo,
							cmpopts.IgnoreUnexported(wrapping.SigInfo{}, wrapping.KeyInfo{}),
						),
					)
				} else {
					require.Empty(t, tc.sig.Bytes())
				}
				return
			}
			require.NoError(t, err)

			require.True(t, tc.f.Closed)

			sigInfo := &wrapping.SigInfo{}
			err = proto.Unmarshal(tc.sig.Bytes(), sigInfo)
			require.NoError(t, err)

			verified, err := keys.VerifySignatureWithPubKey(ctx, sigInfo, []byte(tc.write))
			require.NoError(t, err)
			require.True(t, verified)

			want, err := keys.SignWithPrivKey(ctx, []byte(tc.write))
			require.NoError(t, err)
			assert.Empty(t,
				cmp.Diff(
					want,
					sigInfo,
					cmpopts.IgnoreUnexported(wrapping.SigInfo{}, wrapping.KeyInfo{}),
				),
			)
		})
	}
}
