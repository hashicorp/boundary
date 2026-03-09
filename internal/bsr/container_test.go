// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr/internal/checksum"
	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncBsrKeys(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)
	f := &fstest.MemFS{}

	fc, err := f.New(ctx, fmt.Sprintf(bsrFileNameTemplate, "session-id"))
	require.NoError(t, err)

	c, err := newContainer(ctx, SessionContainer, fc, keys)
	require.NoError(t, err)
	require.NotNil(t, c)

	cases := []struct {
		name      string
		fname     string
		data      []byte
		expErr    bool
		expErrMsg string
	}{
		{
			name:      "no filename",
			data:      []byte("got no name"),
			expErr:    true,
			expErrMsg: "bsr.(container).syncBsrKey: missing file name invalid parameter",
		},
		{
			name:      "no data",
			fname:     "i have a name",
			expErr:    true,
			expErrMsg: "bsr.(container).syncBsrKey: missing data payload invalid parameter",
		},
		{
			name:  "success",
			fname: "i have a name",
			data:  []byte("payload coming thru"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.syncBsrKey(ctx, tc.fname, tc.data)

			if tc.expErr {
				require.EqualError(t, err, tc.expErrMsg)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGetFailedItems(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name               string
		checksumValidation ContainerChecksumValidation
		expectedChecksums  ContainerChecksumValidation
	}{
		{
			name:               "empty",
			checksumValidation: ContainerChecksumValidation{},
			expectedChecksums:  ContainerChecksumValidation{},
		},
		{
			name: "no failed items",
			checksumValidation: ContainerChecksumValidation{
				"test": &FileChecksumValidation{
					Filename: "test",
					Passed:   true,
				},
			},
			expectedChecksums: ContainerChecksumValidation{},
		},
		{
			name: "failed item",
			checksumValidation: ContainerChecksumValidation{
				"test": &FileChecksumValidation{
					Filename: "test",
					Passed:   true,
				},
				"capture": &FileChecksumValidation{
					Filename: "capture",
				},
			},
			expectedChecksums: ContainerChecksumValidation{
				"capture": &FileChecksumValidation{
					Filename: "capture",
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expectedChecksums, tc.checksumValidation.GetFailedItems())
		})
	}
}

func TestSessionValidateChecksums(t *testing.T) {
	ctx := context.Background()
	protocol := TestRegisterSummaryAllocFunc(t)
	cases := []struct {
		name              string
		c                 *container
		expectedChecksums ContainerChecksumValidation
		expectedErr       string
	}{
		{
			name:        "missing checksums",
			c:           &container{},
			expectedErr: "missing checksums",
		},
		{
			name: "missing keys",
			c: &container{
				shaSums: checksum.Sha256Sums{
					"test": []byte("test"),
				},
			},
			expectedErr: "missing keys",
		},
		{
			name: "file does not exist",
			c: func() *container {
				sessionId := "session_123456789"
				keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), sessionId)
				require.NoError(t, err)

				fs := &fstest.MemFS{}
				sc, err := fs.New(ctx, fmt.Sprintf(bsrFileNameTemplate, sessionId))
				require.NoError(t, err)

				c, err := newContainer(ctx, SessionContainer, sc, keys)
				require.NoError(t, err)

				c.shaSums = checksum.Sha256Sums{
					"test": []byte("test"),
				}

				return c
			}(),
			expectedChecksums: ContainerChecksumValidation{
				"test": &FileChecksumValidation{
					Filename: "test",
					Passed:   false,
					Error:    fmt.Errorf("bsr.(container).computeFileChecksum: file test does not exist: does not exist"),
				},
			},
		},
		{
			name: "failed checksum match",
			c: func() *container {
				sessionId := "session_123456789"
				keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), sessionId)
				require.NoError(t, err)

				fs := &fstest.MemFS{}
				sc, err := fs.New(ctx, fmt.Sprintf(bsrFileNameTemplate, sessionId))
				require.NoError(t, err)

				c, err := newContainer(ctx, SessionContainer, sc, keys)
				require.NoError(t, err)

				c.shaSums = checksum.Sha256Sums{
					"test": []byte("test"),
				}

				f, err := c.create(ctx, "test")
				require.NoError(t, err)
				_, err = f.Write([]byte("hello world"))
				require.NoError(t, err)
				require.NoError(t, f.Close())

				return c
			}(),
			expectedChecksums: ContainerChecksumValidation{
				"test": &FileChecksumValidation{
					Filename: "test",
					Passed:   false,
					Error:    fmt.Errorf("checksum mismatch"),
				},
			},
		},
		{
			name: "valid session container",
			c: func() *container {
				sessionId := "session_123456789"
				fs := &fstest.MemFS{}
				keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), sessionId)
				require.NoError(t, err)
				keyFn := func(w kms.WrappedKeys) (kms.UnwrappedKeys, error) {
					u := kms.UnwrappedKeys{
						BsrKey:  keys.BsrKey,
						PrivKey: keys.PrivKey,
					}
					return u, nil
				}

				s, err := NewSession(ctx, TestSessionRecordingMeta(sessionId, protocol), TestSessionMeta(sessionId), fs, keys)
				require.NoError(t, err)
				require.NoError(t, s.EncodeSummary(ctx, &BaseSessionSummary{
					Id:              sessionId,
					ConnectionCount: 1,
					StartTime:       time.Now(),
					EndTime:         time.Now(),
				}))
				require.NoError(t, s.Close(ctx))

				s, err = OpenSession(ctx, sessionId, fs, keyFn)
				require.NoError(t, err)

				return s.container
			}(),
			expectedChecksums: ContainerChecksumValidation{
				bsrPubKeyFileName: &FileChecksumValidation{
					Filename: bsrPubKeyFileName,
					Passed:   true,
				},
				pubKeyBsrSignatureFileName: &FileChecksumValidation{
					Filename: pubKeyBsrSignatureFileName,
					Passed:   true,
				},
				pubKeySelfSignatureFileName: &FileChecksumValidation{
					Filename: pubKeySelfSignatureFileName,
					Passed:   true,
				},
				wrappedBsrKeyFileName: &FileChecksumValidation{
					Filename: wrappedBsrKeyFileName,
					Passed:   true,
				},
				wrappedPrivKeyFileName: &FileChecksumValidation{
					Filename: wrappedPrivKeyFileName,
					Passed:   true,
				},
				sessionMetaFileName: &FileChecksumValidation{
					Filename: sessionMetaFileName,
					Passed:   true,
				},
				"session-recording.meta": &FileChecksumValidation{
					Filename: "session-recording.meta",
					Passed:   true,
				},
				"session-recording-summary.json": &FileChecksumValidation{
					Filename: "session-recording-summary.json",
					Passed:   true,
				},
			},
		},
		{
			name: "valid connection container",
			c: func() *container {
				sessionId := "s_123456789"
				connectionId := "cr_123456789"
				fs := &fstest.MemFS{}
				keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), sessionId)
				require.NoError(t, err)
				keyFn := func(w kms.WrappedKeys) (kms.UnwrappedKeys, error) {
					u := kms.UnwrappedKeys{
						BsrKey:  keys.BsrKey,
						PrivKey: keys.PrivKey,
					}
					return u, nil
				}

				s, err := NewSession(ctx, TestSessionRecordingMeta(sessionId, protocol), TestSessionMeta(sessionId), fs, keys)
				require.NoError(t, err)
				require.NoError(t, s.EncodeSummary(ctx, &BaseSessionSummary{
					Id:              sessionId,
					ConnectionCount: 1,
					StartTime:       time.Now(),
					EndTime:         time.Now(),
				}))

				c, err := s.NewConnection(ctx, &ConnectionRecordingMeta{
					Id: connectionId,
					channels: map[string]bool{
						"test": true,
					},
				})
				require.NoError(t, err)
				require.NoError(t, c.EncodeSummary(ctx, &BaseConnectionSummary{
					Id:           connectionId,
					ChannelCount: 1,
					StartTime:    time.Now(),
					EndTime:      time.Now(),
					BytesUp:      256,
					BytesDown:    256,
				}))

				inbound, err := c.NewRequestsWriter(ctx, Inbound)
				require.NoError(t, err)
				n, err := inbound.Write([]byte("hello world"))
				require.NoError(t, err)
				require.Equal(t, len("hello world"), n)
				closer := inbound.(io.Closer)
				require.NoError(t, closer.Close())

				outbound, err := c.NewRequestsWriter(ctx, Outbound)
				require.NoError(t, err)
				n, err = outbound.Write([]byte("hello world"))
				require.NoError(t, err)
				require.Equal(t, len("hello world"), n)
				closer = outbound.(io.Closer)
				require.NoError(t, closer.Close())

				require.NoError(t, c.Close(ctx))
				require.NoError(t, s.Close(ctx))

				s, err = OpenSession(ctx, sessionId, fs, keyFn)
				require.NoError(t, err)

				c, err = s.OpenConnection(ctx, connectionId)
				require.NoError(t, err)

				return c.container
			}(),
			expectedChecksums: ContainerChecksumValidation{
				"requests-inbound.data": &FileChecksumValidation{
					Filename: "requests-inbound.data",
					Passed:   true,
				},
				"requests-outbound.data": &FileChecksumValidation{
					Filename: "requests-outbound.data",
					Passed:   true,
				},
				"connection-recording.meta": &FileChecksumValidation{
					Filename: "connection-recording.meta",
					Passed:   true,
				},
				"connection-recording-summary.json": &FileChecksumValidation{
					Filename: "connection-recording-summary.json",
					Passed:   true,
				},
			},
		},
		{
			name: "valid channel container",
			c: func() *container {
				sessionId := "s_123456789"
				connectionId := "cr_123456789"
				channelId := "chr_123456789"
				fs := &fstest.MemFS{}
				keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), sessionId)
				require.NoError(t, err)
				keyFn := func(w kms.WrappedKeys) (kms.UnwrappedKeys, error) {
					u := kms.UnwrappedKeys{
						BsrKey:  keys.BsrKey,
						PrivKey: keys.PrivKey,
					}
					return u, nil
				}

				s, err := NewSession(ctx, TestSessionRecordingMeta(sessionId, protocol), TestSessionMeta(sessionId), fs, keys, WithSupportsMultiplex(true))
				require.NoError(t, err)
				require.NoError(t, s.EncodeSummary(ctx, &BaseSessionSummary{
					Id:              sessionId,
					ConnectionCount: 1,
					StartTime:       time.Now(),
					EndTime:         time.Now(),
				}))

				c, err := s.NewConnection(ctx, &ConnectionRecordingMeta{
					Id: connectionId,
					channels: map[string]bool{
						"test": true,
					},
				})
				require.NoError(t, err)
				require.NoError(t, c.EncodeSummary(ctx, &BaseConnectionSummary{
					Id:           connectionId,
					ChannelCount: 1,
					StartTime:    time.Now(),
					EndTime:      time.Now(),
					BytesUp:      256,
					BytesDown:    256,
				}))

				chr, err := c.NewChannel(ctx, &ChannelRecordingMeta{
					Id:   channelId,
					Type: "chan",
				})
				require.NoError(t, err)
				require.NoError(t, chr.EncodeSummary(ctx, &ChannelRecordingMeta{
					Id:   channelId,
					Type: "chan",
				}))

				inboundReq, err := chr.NewRequestsWriter(ctx, Inbound)
				require.NoError(t, err)
				n, err := inboundReq.Write([]byte("hello world"))
				require.NoError(t, err)
				require.Equal(t, len("hello world"), n)
				closer := inboundReq.(io.Closer)
				require.NoError(t, closer.Close())

				outboundReq, err := chr.NewRequestsWriter(ctx, Outbound)
				require.NoError(t, err)
				n, err = outboundReq.Write([]byte("hello world"))
				require.NoError(t, err)
				require.Equal(t, len("hello world"), n)
				closer = outboundReq.(io.Closer)
				require.NoError(t, closer.Close())

				inboundMsg, err := chr.NewMessagesWriter(ctx, Inbound)
				require.NoError(t, err)
				n, err = inboundMsg.Write([]byte("hello world"))
				require.NoError(t, err)
				require.Equal(t, len("hello world"), n)
				closer = inboundMsg.(io.Closer)
				require.NoError(t, closer.Close())

				outboundMsg, err := chr.NewMessagesWriter(ctx, Outbound)
				require.NoError(t, err)
				n, err = outboundMsg.Write([]byte("hello world"))
				require.NoError(t, err)
				require.Equal(t, len("hello world"), n)
				closer = outboundMsg.(io.Closer)
				require.NoError(t, closer.Close())

				require.NoError(t, chr.Close(ctx))
				require.NoError(t, c.Close(ctx))
				require.NoError(t, s.Close(ctx))

				s, err = OpenSession(ctx, sessionId, fs, keyFn)
				require.NoError(t, err)

				c, err = s.OpenConnection(ctx, connectionId)
				require.NoError(t, err)

				chr, err = c.OpenChannel(ctx, channelId)
				require.NoError(t, err)

				return chr.container
			}(),
			expectedChecksums: ContainerChecksumValidation{
				"requests-inbound.data": &FileChecksumValidation{
					Filename: "requests-inbound.data",
					Passed:   true,
				},
				"requests-outbound.data": &FileChecksumValidation{
					Filename: "requests-outbound.data",
					Passed:   true,
				},
				"messages-inbound.data": &FileChecksumValidation{
					Filename: "messages-inbound.data",
					Passed:   true,
				},
				"messages-outbound.data": &FileChecksumValidation{
					Filename: "messages-outbound.data",
					Passed:   true,
				},
				"channel-recording.meta": &FileChecksumValidation{
					Filename: "channel-recording.meta",
					Passed:   true,
				},
				"channel-recording-summary.json": &FileChecksumValidation{
					Filename: "channel-recording-summary.json",
					Passed:   true,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validatedChecksums, err := tc.c.ValidateChecksums(ctx)
			if tc.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErr)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, validatedChecksums)

			require.Equal(t, len(tc.expectedChecksums), len(validatedChecksums))
			for fileName, expectedStatus := range tc.expectedChecksums {
				actualStatus, ok := validatedChecksums[fileName]
				require.True(t, ok, fmt.Sprintf("missing %s", fileName))
				assert.Equal(t, expectedStatus.Passed, actualStatus.Passed)
				assert.Equal(t, expectedStatus.Filename, actualStatus.Filename)
				if expectedStatus.Error == nil {
					assert.NoError(t, actualStatus.Error)
				} else {
					require.Error(t, actualStatus.Error)
					assert.Equal(t, expectedStatus.Error.Error(), actualStatus.Error.Error())
				}
			}
		})
	}
}

func TestComputeFileChecksum(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)
	f := &fstest.MemFS{}

	fc, err := f.New(ctx, fmt.Sprintf(bsrFileNameTemplate, "session-id"))
	require.NoError(t, err)

	c, err := newContainer(ctx, SessionContainer, fc, keys)
	require.NoError(t, err)
	require.NotNil(t, c)

	cases := []struct {
		name        string
		fileName    string
		expectedErr string
	}{
		{
			name:        "empty file name",
			expectedErr: "file  does not exist",
		},
		{
			name:        "file does not exist",
			fileName:    "dne",
			expectedErr: "file dne does not exist",
		},
		{
			name:     "valid",
			fileName: ".journal",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checksum, err := c.computeFileChecksum(ctx, tc.fileName, crypto.WithHexEncoding(true))
			if tc.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErr)
				assert.Empty(t, checksum)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, checksum)
		})
	}
}
