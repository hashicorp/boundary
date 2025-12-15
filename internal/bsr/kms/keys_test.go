// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms_test

import (
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"fmt"
	"testing"

	stdLibEd25519 "crypto/ed25519"

	"github.com/hashicorp/boundary/internal/bsr/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-kms-wrapping/v2/ed25519"
	crypto "github.com/hashicorp/go-kms-wrapping/v2/extras/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCreateBsrKeys(t *testing.T) {
	const (
		ed25519_PrivKey_Length = 64
		ed25519_PubKey_Length  = 32
		bsrKey_Length          = 32

		testMsg = "test-msg"
	)
	t.Parallel()
	testCtx := context.Background()
	testBsrKmsWrapper := kms.TestWrapper(t)
	tests := []struct {
		name            string
		ctx             context.Context
		bsrWrapper      wrapping.Wrapper
		opt             []kms.Option
		sessionId       string
		wantErr         bool
		wantErrMatch    error
		wantErrContains string
	}{
		{
			name:       "success",
			ctx:        testCtx,
			bsrWrapper: testBsrKmsWrapper,
			sessionId:  "session-id",
		},
		{
			name:       "success-WithRandomReader",
			ctx:        testCtx,
			bsrWrapper: testBsrKmsWrapper,
			sessionId:  "session-id",
			opt:        []kms.Option{kms.WithRandomReader(rand.Reader)},
		},
		{
			name:            "missing-session-id",
			ctx:             testCtx,
			bsrWrapper:      testBsrKmsWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing session id",
		},
		{
			name:            "missing-bsr-wrapper",
			ctx:             testCtx,
			sessionId:       "session-id",
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing external bsr wrapper",
		},
		{
			name:       "rand-err-first-read",
			ctx:        testCtx,
			bsrWrapper: testBsrKmsWrapper,
			sessionId:  "session-id",
			opt: []kms.Option{
				kms.WithRandomReader(
					&kms.MockReader{
						WithError:      fmt.Errorf("rand err"),
						WithBytesRead:  32,
						WithMockReadOn: 1,
						Reader:         rand.Reader,
					},
				),
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrGenKey,
			wantErrContains: "error reading random bytes for bsr",
		},
		{
			name:       "rand-bytes-read-first-read",
			ctx:        testCtx,
			bsrWrapper: testBsrKmsWrapper,
			sessionId:  "session-id",
			opt: []kms.Option{
				kms.WithRandomReader(
					&kms.MockReader{
						WithBytesRead:  1,
						WithMockReadOn: 1,
						Reader:         rand.Reader,
					},
				),
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrGenKey,
			wantErrContains: "wanted 32 bytes and got 1",
		},
		{
			name: "encrypt-bsr-err",
			ctx:  testCtx,
			bsrWrapper: &kms.MockWrapper{
				Wrapper:            testBsrKmsWrapper,
				WithEncryptErrorOn: 1,
				EncryptErr:         fmt.Errorf("bsr-encrypt-err"),
			},
			sessionId:       "session-id",
			wantErr:         true,
			wantErrMatch:    kms.ErrEncrypt,
			wantErrContains: "unable to encrypt bsr key",
		},
		{
			name:       "ed25519.Generate-err",
			ctx:        testCtx,
			bsrWrapper: testBsrKmsWrapper,
			sessionId:  "session-id",
			opt: []kms.Option{
				kms.WithRandomReader(
					&kms.MockReader{
						WithError:      fmt.Errorf("rand err"),
						WithBytesRead:  1,
						WithMockReadOn: 2,
						Reader:         rand.Reader,
					},
				),
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrGenKey,
			wantErrContains: "unable to generate bsr ed25519 key-pair",
		},
		{
			name: "encrypt-priv-key-err",
			ctx:  testCtx,
			bsrWrapper: &kms.MockWrapper{
				Wrapper:            testBsrKmsWrapper,
				WithEncryptErrorOn: 2,
				EncryptErr:         fmt.Errorf("encrypt-priv-key-err"),
			},
			sessionId:       "session-id",
			wantErr:         true,
			wantErrMatch:    kms.ErrEncrypt,
			wantErrContains: "unable to encrypt bsr ed25519 priv key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := kms.CreateKeys(tc.ctx, tc.bsrWrapper, tc.sessionId, tc.opt...)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(got)
				if tc.wantErrMatch != nil {
					assert.ErrorIsf(err, tc.wantErrMatch, "expected %q and got err: %+v", tc.wantErrMatch, err)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(got)

			// check the WrappedBsrKey
			assert.NotEmpty(got.WrappedBsrKey)
			assert.NotEmpty(got.WrappedBsrKey.WrappedKey)
			assert.Empty(got.WrappedBsrKey.Key)
			assert.Equal(tc.sessionId, got.WrappedBsrKey.KeyId)
			assert.Equal(wrapping.KeyType_Aes256, got.WrappedBsrKey.KeyType)
			assert.Equal(wrapping.KeyEncoding_Bytes, got.WrappedBsrKey.KeyEncoding)
			assert.Equal([]wrapping.KeyPurpose{wrapping.KeyPurpose_Sign, wrapping.KeyPurpose_Encrypt, wrapping.KeyPurpose_Decrypt}, got.WrappedBsrKey.KeyPurposes)
			var bsrBlob wrapping.BlobInfo
			require.NoError(proto.Unmarshal(got.WrappedBsrKey.WrappedKey, &bsrBlob))
			bsrKeyBytes, err := tc.bsrWrapper.Decrypt(testCtx, &bsrBlob)
			require.NoError(err)
			assert.NotEmpty(bsrKeyBytes)
			assert.Len(bsrKeyBytes, bsrKey_Length)

			// check the WrappedPrivKey
			assert.NotEmpty(got.WrappedPrivKey)
			assert.NotEmpty(got.WrappedPrivKey.WrappedKey)
			assert.Empty(got.WrappedPrivKey.Key)
			assert.Equal(tc.sessionId, got.WrappedPrivKey.KeyId)
			assert.Equal(wrapping.KeyType_Ed25519, got.WrappedPrivKey.KeyType)
			assert.Equal(wrapping.KeyEncoding_Bytes, got.WrappedPrivKey.KeyEncoding)
			assert.Equal([]wrapping.KeyPurpose{wrapping.KeyPurpose_Sign}, got.WrappedPrivKey.KeyPurposes)
			var privKeyBlob wrapping.BlobInfo
			require.NoError(proto.Unmarshal(got.WrappedPrivKey.WrappedKey, &privKeyBlob))
			privKeyBytes, err := tc.bsrWrapper.Decrypt(testCtx, &privKeyBlob)
			require.NoError(err)
			assert.NotEmpty(privKeyBytes)
			assert.Len(privKeyBytes, ed25519_PrivKey_Length)

			// check the bsr key (unwrapped)
			assert.NotEmpty(got.BsrKey)
			assert.NotEmpty(got.BsrKey.Key)
			assert.Empty(got.BsrKey.WrappedKey)
			assert.Equal(tc.sessionId, got.BsrKey.KeyId)
			assert.Equal(wrapping.KeyType_Aes256, got.BsrKey.KeyType)
			assert.Equal(wrapping.KeyEncoding_Bytes, got.BsrKey.KeyEncoding)
			assert.Equal([]wrapping.KeyPurpose{wrapping.KeyPurpose_Sign, wrapping.KeyPurpose_Encrypt, wrapping.KeyPurpose_Decrypt}, got.BsrKey.KeyPurposes)
			assert.Len(got.BsrKey.Key, bsrKey_Length)

			// check the priv key (unwrapped)
			assert.NotEmpty(got.PrivKey)
			assert.NotEmpty(got.PrivKey.Key)
			assert.Empty(got.PrivKey.WrappedKey)
			assert.Equal(tc.sessionId, got.PrivKey.KeyId)
			assert.Equal(wrapping.KeyType_Ed25519, got.PrivKey.KeyType)
			assert.Equal(wrapping.KeyEncoding_Bytes, got.PrivKey.KeyEncoding)
			assert.Equal([]wrapping.KeyPurpose{wrapping.KeyPurpose_Sign}, got.PrivKey.KeyPurposes)
			assert.Len(got.PrivKey.Key, ed25519_PrivKey_Length)

			// check the pub key (unwrapped)
			assert.NotEmpty(got.PubKey)
			assert.NotEmpty(got.PubKey.Key)
			assert.Empty(got.PubKey.WrappedKey)
			assert.Equal(tc.sessionId, got.PubKey.KeyId)
			assert.Equal(wrapping.KeyType_Ed25519, got.PubKey.KeyType)
			assert.Equal(wrapping.KeyEncoding_Bytes, got.PubKey.KeyEncoding)
			assert.Equal([]wrapping.KeyPurpose{wrapping.KeyPurpose_Verify}, got.PubKey.KeyPurposes)
			assert.Len(got.PubKey.Key, ed25519_PubKey_Length)

			// check the pub key self-signature
			// first we'll check it "by hand"
			assert.NotEmpty(got.PubKeySelfSignature)
			s, err := ed25519.NewSigner(testCtx, ed25519.WithPrivKey(stdLibEd25519.PrivateKey(got.PrivKey.Key)))
			require.NoError(err)
			testSig, err := s.Sign(testCtx, stdLibEd25519.PublicKey(got.PubKey.Key))
			require.NoError(err)
			v, err := ed25519.NewVerifier(testCtx, ed25519.WithPubKey(stdLibEd25519.PublicKey(got.PubKey.Key)), wrapping.WithKeyId("session-id"))
			require.NoError(err)
			verified, err := v.Verify(testCtx, stdLibEd25519.PublicKey(got.PubKey.Key), testSig)
			require.NoError(err)
			assert.True(verified)
			// check the keys match
			privKey, err := got.UnwrapPrivKey(testCtx, tc.bsrWrapper)
			require.NoError(err)
			assert.Equal(got.PrivKey.Key, []byte(privKey))
			// now lets' check via the provided oracle
			verified, err = got.VerifyPubKeySelfSignature(testCtx)
			require.NoError(err)
			assert.True(verified)

			// check the pub key bsr signature
			// first we'll check it "by hand"
			assert.NotEmpty(got.PubKeyBsrSignature)
			bsrKeyWrapper := aead.NewWrapper()
			_, err = bsrKeyWrapper.SetConfig(testCtx, wrapping.WithKeyId(got.WrappedBsrKey.KeyId))
			require.NoError(err)
			err = bsrKeyWrapper.SetAesGcmKeyBytes(bsrKeyBytes)
			require.NoError(err)
			marshaledTestSigInfo, err := crypto.HmacSha256(testCtx, stdLibEd25519.PublicKey(got.PubKey.Key), bsrKeyWrapper, crypto.WithMarshaledSigInfo())
			require.NoError(err)
			var testSigInfo wrapping.SigInfo
			err = proto.Unmarshal([]byte(marshaledTestSigInfo), &testSigInfo)
			require.NoError(err)
			assert.Equal(&testSigInfo, got.PubKeyBsrSignature)
			// do the wrappers match
			unwrappedBsrKey, err := got.UnwrapBsrKey(testCtx, tc.bsrWrapper)
			require.NoError(err)
			assert.Equal(bsrKeyWrapper, unwrappedBsrKey)
			// now let's check via the provided oracle using the plaintext
			// got.PrivKey
			verified, err = got.VerifyPubKeyBsrSignature(testCtx)
			require.NoError(err)
			assert.True(verified)
		})
	}
}

func TestBsrKeys_UnwrapBsrKey(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testBsrWrapper := kms.TestWrapper(t)

	testBytes := make([]byte, 32)
	_, err := rand.Read(testBytes)
	require.NoError(t, err)
	testAeadWrapper := aead.NewWrapper()
	_, err = testAeadWrapper.SetConfig(testCtx, wrapping.WithKeyId("session-id"))
	require.NoError(t, err)
	err = testAeadWrapper.SetAesGcmKeyBytes(testBytes)
	require.NoError(t, err)

	bsrBlob, err := testBsrWrapper.Encrypt(testCtx, testBytes)
	require.NoError(t, err)
	marshaledBsrBlob, err := proto.Marshal(bsrBlob)
	require.NoError(t, err)

	tests := []struct {
		name            string
		bsrKeys         *kms.Keys
		bsrWrapper      wrapping.Wrapper
		want            *aead.Wrapper
		wantErr         bool
		wantErrMatch    error
		wantErrContains string
	}{
		{
			name:       "success",
			bsrWrapper: testBsrWrapper,
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					WrappedKey:  marshaledBsrBlob,
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
					KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign, wrapping.KeyPurpose_Encrypt, wrapping.KeyPurpose_Decrypt},
				},
			},
			want: testAeadWrapper,
		},
		{
			name:            "nil-bsr-keys",
			bsrWrapper:      testBsrWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "nil bsr keys",
		},
		{
			name: "missing-bsr-wrapper",
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					WrappedKey:  marshaledBsrBlob,
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
					KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign, wrapping.KeyPurpose_Encrypt, wrapping.KeyPurpose_Decrypt},
				},
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing bsr wrapper",
		},
		{
			name:            "missing-wrapped-bsr-key",
			bsrKeys:         &kms.Keys{},
			bsrWrapper:      testBsrWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing wrapped bsr key",
		},
		{
			name: "missing-wrapped-bsr-key-id",
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					WrappedKey:  marshaledBsrBlob,
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			bsrWrapper:      testBsrWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing wrapped bsr key id",
		},
		{
			name: "missing-wrapped-key-bytes",
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			bsrWrapper:      testBsrWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing wrapped bsr key bytes",
		},
		{
			name: "unexpected-key-type",
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					WrappedKey:  marshaledBsrBlob,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			bsrWrapper:      testBsrWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key type \"Unknown_KeyType\"; expected \"Aes256\"",
		},
		{
			name: "missing-key-encoding",
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					KeyId:      "session-id",
					WrappedKey: marshaledBsrBlob,
					KeyType:    wrapping.KeyType_Aes256,
				},
			},
			bsrWrapper:      testBsrWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key encoding \"Unknown_KeyEncoding\"; expected \"Bytes\"",
		},
		{
			name:       "blob-info-err",
			bsrWrapper: testBsrWrapper,
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					WrappedKey:  []byte("not-blob-info"),
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrDecode,
			wantErrContains: "error unmarshaling wrapped bsr key",
		},
		{
			name:       "decrypt-err",
			bsrWrapper: kms.TestWrapper(t),
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					WrappedKey:  marshaledBsrBlob,
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrDecrypt,
			wantErrContains: "error decrypting wrapped bsr key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.bsrKeys.UnwrapBsrKey(testCtx, tc.bsrWrapper)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(got)
				if tc.wantErrMatch != nil {
					assert.ErrorIsf(err, tc.wantErrMatch, "expected %q and got err: %+v", tc.wantErrMatch, err)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(got)
			assert.Equal(tc.want, got)
			assert.Equal(&wrapping.KeyInfo{
				KeyId:       "session-id",
				Key:         testBytes,
				KeyType:     wrapping.KeyType_Aes256,
				KeyEncoding: wrapping.KeyEncoding_Bytes,
				KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign, wrapping.KeyPurpose_Encrypt, wrapping.KeyPurpose_Decrypt},
			}, tc.bsrKeys.BsrKey)
		})
	}
}

func TestBsrKeys_UnwrapPrivKey(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testBsrWrapper := kms.TestWrapper(t)

	_, priv, err := stdLibEd25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	bsrBlob, err := testBsrWrapper.Encrypt(testCtx, priv)
	require.NoError(t, err)
	marshaledBsrBlob, err := proto.Marshal(bsrBlob)
	require.NoError(t, err)

	badBlob, err := testBsrWrapper.Encrypt(testCtx, []byte("bad-key-len"))
	require.NoError(t, err)
	marshaledBadBlob, err := proto.Marshal(badBlob)
	require.NoError(t, err)

	tests := []struct {
		name            string
		bsrKeys         *kms.Keys
		bsrWrapper      wrapping.Wrapper
		want            stdLibEd25519.PrivateKey
		wantErr         bool
		wantErrMatch    error
		wantErrContains string
	}{
		{
			name:       "success",
			bsrWrapper: testBsrWrapper,
			bsrKeys: &kms.Keys{
				WrappedPrivKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					WrappedKey:  marshaledBsrBlob,
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
					KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
				},
			},
			want: priv,
		},
		{
			name:            "nil-bsr-keys",
			bsrWrapper:      testBsrWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "nil bsr keys",
		},
		{
			name: "missing-bsr-wrapper",
			bsrKeys: &kms.Keys{
				WrappedPrivKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					WrappedKey:  marshaledBsrBlob,
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing bsr wrapper",
		},
		{
			name:            "missing-wrapped-priv-key",
			bsrKeys:         &kms.Keys{},
			bsrWrapper:      testBsrWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing wrapped priv key",
		},
		{
			name: "missing-wrapped-bsr-key-id",
			bsrKeys: &kms.Keys{
				WrappedPrivKey: &wrapping.KeyInfo{
					WrappedKey:  marshaledBsrBlob,
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			bsrWrapper:      testBsrWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing wrapped priv key id",
		},
		{
			name: "missing-wrapped-key-bytes",
			bsrKeys: &kms.Keys{
				WrappedPrivKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			bsrWrapper:      testBsrWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing wrapped priv key bytes",
		},
		{
			name: "missing-key-type",
			bsrKeys: &kms.Keys{
				WrappedPrivKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					WrappedKey:  marshaledBsrBlob,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			bsrWrapper:      testBsrWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key type \"Unknown_KeyType\"; expected \"Ed25519\"",
		},
		{
			name: "missing-key-encoding",
			bsrKeys: &kms.Keys{
				WrappedPrivKey: &wrapping.KeyInfo{
					KeyId:      "session-id",
					WrappedKey: marshaledBsrBlob,
					KeyType:    wrapping.KeyType_Ed25519,
				},
			},
			bsrWrapper:      testBsrWrapper,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key encoding \"Unknown_KeyEncoding\"; expected \"Bytes\"",
		},
		{
			name:       "blob-info-err",
			bsrWrapper: testBsrWrapper,
			bsrKeys: &kms.Keys{
				WrappedPrivKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					WrappedKey:  []byte("not-blob-info"),
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrDecode,
			wantErrContains: "error unmarshaling wrapped priv key",
		},
		{
			name:       "decrypt-err",
			bsrWrapper: kms.TestWrapper(t),
			bsrKeys: &kms.Keys{
				WrappedPrivKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					WrappedKey:  marshaledBsrBlob,
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrDecrypt,
			wantErrContains: "error decrypting wrapped priv key",
		},
		{
			name:       "invalid-key-len-err",
			bsrWrapper: testBsrWrapper,
			bsrKeys: &kms.Keys{
				WrappedPrivKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					WrappedKey:  marshaledBadBlob,
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "priv key must be 64 bytes; got 11",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.bsrKeys.UnwrapPrivKey(testCtx, tc.bsrWrapper)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(got)
				if tc.wantErrMatch != nil {
					assert.ErrorIsf(err, tc.wantErrMatch, "expected %q and got err: %+v", tc.wantErrMatch, err)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(got)
			assert.Equal(tc.want, got)
			assert.Equal(&wrapping.KeyInfo{
				KeyId:       "session-id",
				Key:         priv,
				KeyType:     wrapping.KeyType_Ed25519,
				KeyEncoding: wrapping.KeyEncoding_Bytes,
				KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
			}, tc.bsrKeys.PrivKey)
		})
	}
}

func TestBsrKeys_VerifyPubBsrSignature(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testBsrWrapper := kms.TestWrapper(t)

	testBytes := make([]byte, 32)
	_, err := rand.Read(testBytes)
	require.NoError(t, err)
	testAeadWrapper := aead.NewWrapper()
	_, err = testAeadWrapper.SetConfig(testCtx, wrapping.WithKeyId("session-id"))
	require.NoError(t, err)
	err = testAeadWrapper.SetAesGcmKeyBytes(testBytes)
	require.NoError(t, err)

	bsrBlob, err := testBsrWrapper.Encrypt(testCtx, testBytes)
	require.NoError(t, err)
	marshaledBsrBlob, err := proto.Marshal(bsrBlob)
	require.NoError(t, err)

	pub, _, err := stdLibEd25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sigStr, err := crypto.HmacSha256(testCtx, pub, testAeadWrapper, crypto.WithMarshaledSigInfo())
	require.NoError(t, err)
	var testValidPubKeySignature wrapping.SigInfo
	require.NoError(t, proto.Unmarshal([]byte(sigStr), &testValidPubKeySignature))

	invalidPub, _, err := stdLibEd25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sigStr, err = crypto.HmacSha256(testCtx, invalidPub, testAeadWrapper, crypto.WithMarshaledSigInfo())
	require.NoError(t, err)
	var testInValidPubKeySignature wrapping.SigInfo
	require.NoError(t, proto.Unmarshal([]byte(sigStr), &testInValidPubKeySignature))

	tests := []struct {
		name            string
		bsrKeys         *kms.Keys
		opt             []kms.Option
		want            bool
		wantErr         bool
		wantErrMatch    error
		wantErrContains string
	}{
		{
			name: "not-equal",
			bsrKeys: &kms.Keys{
				BsrKey: &wrapping.KeyInfo{
					Key:         testBytes,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testInValidPubKeySignature,
			},
			want: false,
		},
		{
			name: "success",
			bsrKeys: &kms.Keys{
				BsrKey: &wrapping.KeyInfo{
					Key:         testBytes,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			want: true,
		},
		{
			name: "success-with-wrapper",
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					WrappedKey:  marshaledBsrBlob,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			opt:  []kms.Option{kms.WithBsrWrapper(testBsrWrapper)},
			want: true,
		},
		{
			name:            "nil-bsr-keys",
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "nil bsr keys",
		},
		{
			name: "missing-bsr-key-and-wrapped-bsr-key",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing bsr key and wrapped bsr key",
		},
		{
			name: "missing-bsr-key-bytes",
			bsrKeys: &kms.Keys{
				BsrKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing bsr key bytes",
		},
		{
			name: "missing-wrapped-bsr-key-bytes",
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			opt:             []kms.Option{kms.WithBsrWrapper(testBsrWrapper)},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing wrapped bsr key bytes",
		},
		{
			name: "missing-pub-key",
			bsrKeys: &kms.Keys{
				BsrKey: &wrapping.KeyInfo{
					Key:         testBytes,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing pub key",
		},
		{
			name: "missing-signature",
			bsrKeys: &kms.Keys{
				BsrKey: &wrapping.KeyInfo{
					Key:         testBytes,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing pub key signature",
		},
		{
			name: "bsr-key-invalid-key-type",
			bsrKeys: &kms.Keys{
				BsrKey: &wrapping.KeyInfo{
					Key:         testBytes,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_EdsaP521,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key type \"EdsaP521\"; expected \"Aes256\"",
		},
		{
			name: "bsr-key-invalid-key-encoding",
			bsrKeys: &kms.Keys{
				BsrKey: &wrapping.KeyInfo{
					Key:         testBytes,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Pkix,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key encoding \"Pkix\"; expected \"Bytes\"",
		},
		{
			name: "wrapped-bsr-key-missing-wrapper",
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					WrappedKey:  marshaledBsrBlob,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing bsr wrapper",
		},
		{
			name: "wrapped-bsr-key-invalid-key-type",
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					WrappedKey:  marshaledBsrBlob,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Rsa4096,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			opt:             []kms.Option{kms.WithBsrWrapper(testBsrWrapper)},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key type \"Rsa4096\"; expected \"Aes256\"",
		},
		{
			name: "wrapped-bsr-key-invalid-key-encoding",
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					WrappedKey:  marshaledBsrBlob,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Pkix,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			opt:             []kms.Option{kms.WithBsrWrapper(testBsrWrapper)},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key encoding \"Pkix\"; expected \"Bytes\"",
		},
		{
			name: "wrapped-bsr-key-invalid-wrapper",
			bsrKeys: &kms.Keys{
				WrappedBsrKey: &wrapping.KeyInfo{
					WrappedKey:  marshaledBsrBlob,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			opt:             []kms.Option{kms.WithBsrWrapper(kms.TestWrapper(t))},
			wantErr:         true,
			wantErrMatch:    kms.ErrDecrypt,
			wantErrContains: "error unwrapping bsr key",
		},
		{
			name: "mismatched-key-id",
			bsrKeys: &kms.Keys{
				BsrKey: &wrapping.KeyInfo{
					Key:         testBytes,
					KeyId:       "mismatched-key-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeyBsrSignature: &testValidPubKeySignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "signature key id \"session-id\" doesn't match verifying key id \"mismatched-key-id\"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.bsrKeys.VerifyPubKeyBsrSignature(testCtx, tc.opt...)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(got)
				if tc.wantErrMatch != nil {
					assert.ErrorIsf(err, tc.wantErrMatch, "expected %q and got err: %+v", tc.wantErrMatch, err)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

func TestBsrKeys_VerifyPubKeySelfSignature(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	pub, priv, err := stdLibEd25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privKeySigner, err := ed25519.NewSigner(testCtx, ed25519.WithPrivKey(priv), wrapping.WithKeyId("session-id"))
	require.NoError(t, err)
	testPubKeySelfSignature, err := privKeySigner.Sign(testCtx, pub)
	require.NoError(t, err)
	testInvalidPubKeySelfSignature, err := privKeySigner.Sign(testCtx, []byte("not-the-pub-key"))
	require.NoError(t, err)

	tests := []struct {
		name            string
		bsrKeys         *kms.Keys
		opt             []kms.Option
		want            bool
		wantErr         bool
		wantErrMatch    error
		wantErrContains string
	}{
		{
			name: "not-equal",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeySelfSignature: testInvalidPubKeySelfSignature,
			},
			want: false,
		},
		{
			name: "success",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeySelfSignature: testPubKeySelfSignature,
			},
			want: true,
		},
		{
			name: "missing-pub-key",
			bsrKeys: &kms.Keys{
				PubKeySelfSignature: testPubKeySelfSignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing pub key",
		},

		{
			name: "missing-pub-key-bytes",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeySelfSignature: testPubKeySelfSignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing pub key bytes",
		},
		{
			name: "invalid-key-type",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeySelfSignature: testPubKeySelfSignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key type \"Aes256\"; expected \"Ed25519\"",
		},
		{
			name: "invalid-key-encoding",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Pkcs8,
				},
				PubKeySelfSignature: testPubKeySelfSignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key encoding \"Pkcs8\"; expected \"Bytes\"",
		},
		{
			name: "missing-signature",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing pub key self signature",
		},
		{
			name: "mismatched-key-id",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					Key:         pub,
					KeyId:       "mismatched-key-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeySelfSignature: testPubKeySelfSignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "pub self signature key id \"session-id\" doesn't match verifying pub key id \"mismatched-key-id\"",
		},
		{
			name: "bad-pub-key",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					Key:         []byte("bad-pub-key"),
					KeyId:       "session-id",
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
				},
				PubKeySelfSignature: testPubKeySelfSignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "expected public key with 32 bytes and got 11",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.bsrKeys.VerifyPubKeySelfSignature(testCtx)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(got)
				if tc.wantErrMatch != nil {
					assert.ErrorIsf(err, tc.wantErrMatch, "expected %q and got err: %+v", tc.wantErrMatch, err)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

func TestBsrKeys_VerifySignatureWithPubKey(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()

	keys, err := kms.CreateKeys(testCtx, kms.TestWrapper(t), "session")
	require.NoError(t, err)

	message := "this is a super secret message!"
	sig, err := keys.SignWithPrivKey(testCtx, []byte(message))
	require.NoError(t, err)
	require.NotNil(t, sig)
	badMessage := "bad message###oh nooo"

	tests := []struct {
		name            string
		bsrKeys         *kms.Keys
		verifyMessage   string
		opt             []kms.Option
		want            bool
		wantErr         bool
		wantErrMatch    error
		wantErrContains string
	}{
		{
			name:          "success",
			bsrKeys:       keys,
			verifyMessage: message,
			want:          true,
		},
		{
			name:          "message-not-verified",
			bsrKeys:       keys,
			verifyMessage: badMessage,
			want:          false,
		},
		{
			name: "missing-pub-key",
			bsrKeys: &kms.Keys{
				PubKeySelfSignature: keys.PubKeySelfSignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing pub key",
		},

		{
			name: "missing-pub-key-bytes",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					KeyId:       keys.PubKey.KeyId,
					KeyType:     keys.PubKey.KeyType,
					KeyEncoding: keys.PubKey.KeyEncoding,
				},
				PubKeySelfSignature: keys.PubKeySelfSignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing pub key bytes",
		},
		{
			name: "invalid-key-type",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					Key:         keys.PubKey.Key,
					KeyId:       keys.PubKey.KeyId,
					KeyType:     wrapping.KeyType_Aes256,
					KeyEncoding: keys.PubKey.KeyEncoding,
				},
				PubKeySelfSignature: keys.PubKeySelfSignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key type \"Aes256\"; expected \"Ed25519\"",
		},
		{
			name: "invalid-key-encoding",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					Key:         keys.PubKey.Key,
					KeyId:       keys.PubKey.KeyId,
					KeyType:     keys.PubKey.KeyType,
					KeyEncoding: wrapping.KeyEncoding_Pkcs8,
				},
				PubKeySelfSignature: keys.PubKeySelfSignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key encoding \"Pkcs8\"; expected \"Bytes\"",
		},
		{
			name: "bad-pub-key",
			bsrKeys: &kms.Keys{
				PubKey: &wrapping.KeyInfo{
					Key:         []byte("bad-pub-key"),
					KeyId:       keys.PubKey.KeyId,
					KeyType:     keys.PubKey.KeyType,
					KeyEncoding: keys.PubKey.KeyEncoding,
				},
				PubKeySelfSignature: keys.PubKeySelfSignature,
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "expected public key with 32 bytes and got 11",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := tc.bsrKeys.VerifySignatureWithPubKey(testCtx, sig, []byte(tc.verifyMessage))
			if tc.wantErr {
				require.Error(err)
				assert.Empty(got)
				if tc.wantErrMatch != nil {
					assert.ErrorIsf(err, tc.wantErrMatch, "expected %q and got err: %+v", tc.wantErrMatch, err)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

func TestBsrKeys_SignWithPrivKey(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()

	_, priv, err := stdLibEd25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	testMsg := []byte("test-msg")
	testSig, err := priv.Sign(nil, testMsg, stdcrypto.Hash(0))
	require.NoError(t, err)

	tests := []struct {
		name            string
		bsrKeys         *kms.Keys
		msg             []byte
		want            *wrapping.SigInfo
		wantErr         bool
		wantErrMatch    error
		wantErrContains string
	}{
		{
			name: "success",
			bsrKeys: &kms.Keys{
				PrivKey: &wrapping.KeyInfo{
					Key:         priv,
					KeyType:     wrapping.KeyType_Ed25519,
					KeyId:       "session-id",
					KeyEncoding: wrapping.KeyEncoding_Bytes,
					KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
				},
			},
			msg: testMsg,
			want: &wrapping.SigInfo{
				KeyInfo: &wrapping.KeyInfo{
					KeyType:     wrapping.KeyType_Ed25519,
					KeyId:       "session-id",
					KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
				},
				Signature: testSig,
			},
		},
		{
			name: "missing-msg",
			bsrKeys: &kms.Keys{
				PrivKey: &wrapping.KeyInfo{
					Key:         priv,
					KeyType:     wrapping.KeyType_Ed25519,
					KeyId:       "session-id",
					KeyEncoding: wrapping.KeyEncoding_Bytes,
					KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
				},
			},
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing msg",
		},
		{
			name:            "missing-priv-key",
			bsrKeys:         &kms.Keys{},
			msg:             testMsg,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing priv key",
		},
		{
			name: "missing-priv-key-id",
			bsrKeys: &kms.Keys{
				PrivKey: &wrapping.KeyInfo{
					Key:         priv,
					KeyType:     wrapping.KeyType_Ed25519,
					KeyEncoding: wrapping.KeyEncoding_Bytes,
					KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
				},
			},
			msg:             testMsg,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing priv key id",
		},
		{
			name: "missing-key-bytes",
			bsrKeys: &kms.Keys{
				PrivKey: &wrapping.KeyInfo{
					KeyType:     wrapping.KeyType_Ed25519,
					KeyId:       "session-id",
					KeyEncoding: wrapping.KeyEncoding_Bytes,
					KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
				},
			},
			msg:             testMsg,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "missing priv key bytes",
		},
		{
			name: "invalid-key-type",
			bsrKeys: &kms.Keys{
				PrivKey: &wrapping.KeyInfo{
					Key:         priv,
					KeyId:       "session-id",
					KeyEncoding: wrapping.KeyEncoding_Bytes,
					KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
				},
			},
			msg:             testMsg,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key type \"Unknown_KeyType\"; expected \"Ed25519\"",
		},
		{
			name: "invalid-key-encoding",
			bsrKeys: &kms.Keys{
				PrivKey: &wrapping.KeyInfo{
					Key:         priv,
					KeyType:     wrapping.KeyType_Ed25519,
					KeyId:       "session-id",
					KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
				},
			},
			msg:             testMsg,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "unexpected key encoding \"Unknown_KeyEncoding\"; expected \"Bytes\"",
		},
		{
			name: "invalid-key-len",
			bsrKeys: &kms.Keys{
				PrivKey: &wrapping.KeyInfo{
					Key:         []byte("invalid-len"),
					KeyType:     wrapping.KeyType_Ed25519,
					KeyId:       "session-id",
					KeyEncoding: wrapping.KeyEncoding_Bytes,
					KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
				},
			},
			msg:             testMsg,
			wantErr:         true,
			wantErrMatch:    kms.ErrInvalidParameter,
			wantErrContains: "expected priv key with 64 bytes and got 11",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.bsrKeys.SignWithPrivKey(testCtx, tc.msg)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(got)
				if tc.wantErrMatch != nil {
					assert.ErrorIsf(err, tc.wantErrMatch, "expected %q and got err: %+v", tc.wantErrMatch, err)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}
