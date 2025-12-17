// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

func Test_HmacSha256(t *testing.T) {
	testCtx := context.Background()
	testWrapper := TestWrapper(t)
	tests := []struct {
		name      string
		data      []byte
		wrapper   wrapping.Wrapper
		salt      []byte
		info      []byte
		opts      []Option
		wantHmac  string
		wantErr   bool
		wantErrIs error
	}{
		{
			name:      "missing data",
			wrapper:   testWrapper,
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:      "missing wrapper",
			data:      []byte("test"),
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:      "prk-and-ed25519",
			data:      []byte("test"),
			wrapper:   testWrapper,
			opts:      []Option{WithPrk([]byte("prk")), WithEd25519()},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:      "prk-and-wrapper",
			data:      []byte("test"),
			wrapper:   testWrapper,
			opts:      []Option{WithPrk([]byte("prk")), WithEd25519()},
			wantErr:   true,
			wantErrIs: ErrInvalidParameter,
		},
		{
			name:     "blake2b-with-prefix",
			data:     []byte("test"),
			wrapper:  testWrapper,
			opts:     []Option{WithPrefix("prefix:")},
			wantHmac: testWithBlake2b(t, []byte("test"), testWrapper, nil, nil, WithPrefix("prefix:")),
		},
		{
			name:     "blake2b-with-prefix-with-base64",
			data:     []byte("test"),
			wrapper:  testWrapper,
			opts:     []Option{WithPrefix("prefix:"), WithBase64Encoding()},
			wantHmac: testWithBlake2b(t, []byte("test"), testWrapper, nil, nil, WithPrefix("prefix:"), WithBase64Encoding()),
		},
		{
			name:     "blake2b-with-prefix-with-base58",
			data:     []byte("test"),
			wrapper:  testWrapper,
			opts:     []Option{WithPrefix("prefix:"), WithBase58Encoding()},
			wantHmac: testWithBlake2b(t, []byte("test"), testWrapper, nil, nil, WithPrefix("prefix:"), WithBase58Encoding()),
		},
		{
			name:     "with-prk",
			data:     []byte("test"),
			opts:     []Option{WithPrk([]byte("prk-0123456789012345678901234567890"))},
			wantHmac: testWithBlake2b(t, []byte("test"), testWrapper, nil, nil, WithPrk([]byte("prk-0123456789012345678901234567890"))),
		},
		{
			name:     "withEd25519",
			data:     []byte("test"),
			wrapper:  testWrapper,
			opts:     []Option{WithEd25519()},
			wantHmac: testWithEd25519(t, []byte("test"), testWrapper, nil, nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			hm, err := HmacSha256(testCtx, tt.data, tt.wrapper, tt.salt, tt.info, tt.opts...)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.ErrorIs(err, tt.wantErrIs)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantHmac, hm)
		})
	}

	t.Run("HmacSha256WithPrk", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		hm, err := HmacSha256WithPrk(testCtx, []byte("test"), []byte("prk-0123456789012345678901234567890"))
		require.NoError(err)
		want := testWithBlake2b(t, []byte("test"), testWrapper, nil, nil, WithPrk([]byte("prk-0123456789012345678901234567890")))
		assert.Equal(want, hm)
	})
}

func testWithEd25519(t *testing.T, data []byte, w wrapping.Wrapper, salt, info []byte, opt ...Option) string {
	t.Helper()
	require := require.New(t)
	reader, err := NewDerivedReader(context.Background(), w, 32, salt, info)
	require.NoError(err)
	edKey, _, err := ed25519.GenerateKey(reader)
	require.NoError(err)
	var key [32]byte
	n := copy(key[:], edKey)
	require.Equal(n, 32)
	return testHmac(t, key[:], data, opt...)
}

func testWithBlake2b(t *testing.T, data []byte, w wrapping.Wrapper, salt, info []byte, opt ...Option) string {
	t.Helper()
	require := require.New(t)
	require.NotNil(data)
	require.NotNil(w)
	opts, err := getOpts(opt...)
	require.NoError(err)
	var key [32]byte
	switch {
	case opts.withPrk != nil:
		key = blake2b.Sum256(opts.withPrk)
	default:
		reader, err := NewDerivedReader(context.Background(), w, 32, salt, info)
		require.NoError(err)
		readerKey := make([]byte, 32)
		n, err := io.ReadFull(reader, readerKey)
		require.NoError(err)
		require.Equal(n, 32)
		key = blake2b.Sum256(readerKey)
	}
	return testHmac(t, key[:], data, opt...)
}

func testHmac(t *testing.T, key, data []byte, opt ...Option) string {
	t.Helper()
	require := require.New(t)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	hmac := mac.Sum(nil)
	var hmacString string
	opts, err := getOpts(opt...)
	require.NoError(err)
	switch {
	case opts.withBase64Encoding:
		hmacString = base64.RawURLEncoding.EncodeToString(hmac)
	case opts.withBase58Encoding:
		hmacString = base58.Encode(hmac)
	default:
		hmacString = string(hmac)
	}
	if opts.withPrefix != "" {
		return opts.withPrefix + hmacString
	}
	return hmacString
}
