// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/checksum"
	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBSR_Validate_Valid(t *testing.T) {
	ctx := context.Background()

	connectionId := "test_connection"
	channelId := "test_channel"
	sessionId := "s_01234567881"
	protocol := Protocol("TEST_VALIDATE_PROTOCOL")

	err := RegisterSummaryAllocFunc(protocol, ChannelContainer, func(ctx context.Context) Summary {
		return &BaseChannelSummary{Id: "chr_123456789", ConnectionRecordingId: connectionId}
	})
	require.NoError(t, err)

	err = RegisterSummaryAllocFunc(protocol, SessionContainer, func(ctx context.Context) Summary {
		return &BaseSessionSummary{Id: "s_123456789", ConnectionCount: 1}
	})
	require.NoError(t, err)

	err = RegisterSummaryAllocFunc(protocol, ConnectionContainer, func(ctx context.Context) Summary {
		return &BaseConnectionSummary{Id: "cr_123456789", ChannelCount: 1}
	})
	require.NoError(t, err)

	// Setup keys
	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), sessionId)
	require.NoError(t, err)

	keyFn := func(w kms.WrappedKeys) (kms.UnwrappedKeys, error) {
		u := kms.UnwrappedKeys{
			BsrKey:  keys.BsrKey,
			PrivKey: keys.PrivKey,
		}
		return u, nil
	}

	cases := []struct {
		name                            string
		protocol                        Protocol
		storage                         storage.FS
		sessionId                       string
		sessionRecordingId              string
		expectedSessionChecksums        ContainerChecksumValidation
		expectedConnectionChecksums     ContainerChecksumValidation
		expectedChannelChecksums        ContainerChecksumValidation
		expectedSessionContainerSize    int
		expectedConnectionContainerSize int
		expectedChannelContainerSize    int
		wantErr                         error
	}{
		{
			name:               "valid BSR with multiple connections and channels",
			sessionId:          "s_01234567881",
			sessionRecordingId: "sr_01234567881",
			storage: func() storage.FS {
				// sessionId := "s_01234567881"
				sessionRecordingId := "sr_01234567881"
				fs := &fstest.MemFS{}
				// Set up session
				srm := &SessionRecordingMeta{
					Id:       sessionRecordingId,
					Protocol: protocol,
				}
				sessionMeta := TestSessionMeta(sessionId)

				sesh, err := NewSession(ctx, srm, sessionMeta, fs, keys, WithSupportsMultiplex(true))
				require.NoError(t, err)
				require.NotNil(t, sesh)

				// Encode session summary
				sesh.EncodeSummary(ctx, &BaseSessionSummary{
					Id: channelId,
				})

				// Set up connection 1
				conn1, err := sesh.NewConnection(ctx, &ConnectionRecordingMeta{Id: connectionId + "_1"})
				require.NoError(t, err)
				require.NotNil(t, conn1)

				// Encode connection 2 summary
				err = conn1.EncodeSummary(ctx, &BaseConnectionSummary{
					Id:           connectionId + ".1",
					ChannelCount: 1,
				})
				require.NoError(t, err)

				// Set up connection 2
				conn2, err := sesh.NewConnection(ctx, &ConnectionRecordingMeta{Id: connectionId + "_2"})
				require.NoError(t, err)
				require.NotNil(t, conn1)

				// Encode connection 2 summary
				err = conn2.EncodeSummary(ctx, &BaseConnectionSummary{
					Id:           connectionId + ".2",
					ChannelCount: 1,
				})
				require.NoError(t, err)

				// Setup Channels with Connection 1
				ch1, err := conn1.NewChannel(ctx, &ChannelRecordingMeta{
					Id:   channelId + "_1",
					Type: "chan",
				})
				require.NoError(t, err)
				require.NotNil(t, ch1)

				err = ch1.EncodeSummary(ctx, &BaseChannelSummary{
					Id:                    channelId + "_1",
					ConnectionRecordingId: connectionId + "_1",
				})
				require.NoError(t, err)

				ch2, err := conn1.NewChannel(ctx, &ChannelRecordingMeta{
					Id:   channelId + "_2",
					Type: "chan",
				})
				require.NoError(t, err)
				require.NotNil(t, ch2)

				err = ch2.EncodeSummary(ctx, &BaseChannelSummary{
					Id:                    channelId + "_2",
					ConnectionRecordingId: connectionId + "_1",
				})
				require.NoError(t, err)

				// Setup Channels with Connection 2
				ch3, err := conn2.NewChannel(ctx, &ChannelRecordingMeta{
					Id:   channelId + "_1",
					Type: "chan",
				})
				require.NoError(t, err)
				require.NotNil(t, ch3)

				err = ch3.EncodeSummary(ctx, &BaseChannelSummary{
					Id:                    channelId + "_1",
					ConnectionRecordingId: connectionId + "_2",
				})
				require.NoError(t, err)

				ch4, err := conn2.NewChannel(ctx, &ChannelRecordingMeta{
					Id:   channelId + "_2",
					Type: "chan",
				})
				require.NoError(t, err)
				require.NotNil(t, ch4)

				// Encode channel summary
				err = ch4.EncodeSummary(ctx, &BaseChannelSummary{
					Id:                    channelId + "_2",
					ConnectionRecordingId: connectionId + "_2",
				})
				require.NoError(t, err)

				require.NoError(t, ch1.Close(ctx))
				require.NoError(t, ch2.Close(ctx))
				require.NoError(t, ch3.Close(ctx))
				require.NoError(t, ch4.Close(ctx))
				require.NoError(t, conn1.Close(ctx))
				require.NoError(t, conn2.Close(ctx))
				require.NoError(t, sesh.Close(ctx))

				return fs
			}(),
			expectedSessionChecksums: ContainerChecksumValidation{
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
			expectedConnectionChecksums: ContainerChecksumValidation{
				"connection-recording-summary.json": &FileChecksumValidation{
					Filename: "connection-recording-summary.json",
					Passed:   true,
				},
				"connection-recording.meta": &FileChecksumValidation{
					Filename: "connection-recording.meta",
					Passed:   true,
				},
			},
			expectedChannelChecksums: ContainerChecksumValidation{
				"channel-recording-summary.json": &FileChecksumValidation{
					Filename: "channel-recording-summary.json",
					Passed:   true,
				},
				"channel-recording.meta": &FileChecksumValidation{
					Filename: "channel-recording.meta",
					Passed:   true,
				},
			},
			expectedSessionContainerSize:    2,
			expectedConnectionContainerSize: 2,
			expectedChannelContainerSize:    0,
		},
		{
			name:               "Failed checksum",
			sessionRecordingId: "sr_21234567881",
			storage: func() storage.FS {
				fs := &fstest.MemFS{}
				tmpFileName := "Test"
				// Set up session
				srm := &SessionRecordingMeta{
					Id:       "sr_21234567881",
					Protocol: protocol,
				}
				sessionMeta := TestSessionMeta(sessionId)

				session, err := NewSession(ctx, srm, sessionMeta, fs, keys, WithSupportsMultiplex(true))
				require.NoError(t, err)
				require.NotNil(t, session)

				// Encode session summary
				session.EncodeSummary(ctx, &BaseSessionSummary{
					Id: channelId,
				})

				testFile, err := session.container.container.Create(ctx, tmpFileName)
				require.NoError(t, err)

				_, err = testFile.Write([]byte("hello world"))
				require.NoError(t, err)
				tfc, err := checksum.NewFile(ctx, testFile, session.checksums)
				require.NoError(t, err)
				require.NotNil(t, tfc)
				require.NoError(t, tfc.Close())

				require.NoError(t, session.Close(ctx))

				openSesh, err := OpenSession(ctx, srm.Id, fs, keyFn)
				require.NoError(t, err)
				require.NotNil(t, openSesh)

				openedTestFile, err := openSesh.container.container.OpenFile(ctx, tmpFileName, storage.WithCreateFile(), storage.WithFileAccessMode(storage.ReadWrite))
				require.NoError(t, err)

				_, err = openedTestFile.Write([]byte("invalid text"))
				require.NoError(t, err)
				require.NoError(t, openedTestFile.Close())

				return fs
			}(),

			expectedSessionChecksums: ContainerChecksumValidation{
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
				"Test": &FileChecksumValidation{
					Filename: "Test",
					Passed:   false,
					Error:    errors.New("checksum mismatch"),
				},
			},
			expectedConnectionChecksums: ContainerChecksumValidation{
				"connection-recording-summary.json": &FileChecksumValidation{
					Filename: "connection-recording-summary.json",
					Passed:   true,
				},
				"connection-recording.meta": &FileChecksumValidation{
					Filename: "connection-recording.meta",
					Passed:   true,
				},
			},
			expectedChannelChecksums: ContainerChecksumValidation{
				"channel-recording-summary.json": &FileChecksumValidation{
					Filename: "channel-recording-summary.json",
					Passed:   true,
				},
				"channel-recording.meta": &FileChecksumValidation{
					Filename: "channel-recording.meta",
					Passed:   true,
				},
			},
			expectedSessionContainerSize:    2,
			expectedConnectionContainerSize: 2,
			expectedChannelContainerSize:    0,
		},
		{
			name:    "missing session recording id parameter",
			wantErr: errors.New("bsr.Validate: missing session recording id: invalid parameter"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validation, err := Validate(ctx, tc.sessionRecordingId, tc.storage, keyFn)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			require.NotNil(t, validation)

			// Validate Session
			assert.Equal(t, tc.sessionRecordingId, validation.SessionRecordingId)
			assert.Equal(t, SessionContainer, validation.SessionRecordingValidation.ContainerType)
			assert.Equal(t, len(tc.expectedSessionChecksums), len(validation.SessionRecordingValidation.FileChecksumValidations))
			assert.Equal(t, tc.expectedSessionChecksums, validation.SessionRecordingValidation.FileChecksumValidations)

			// Validate Multiple Connections
			for _, connection := range validation.SessionRecordingValidation.SubContainers {
				require.NotNil(t, connection)
				assert.Equal(t, ConnectionContainer, connection.ContainerType)
				assert.Equal(t, tc.expectedConnectionContainerSize, len(connection.SubContainers))
				assert.Equal(t, len(tc.expectedConnectionChecksums), len(connection.FileChecksumValidations))
				assert.Equal(t, tc.expectedConnectionChecksums, connection.FileChecksumValidations)

				// Validate Multiple Channels
				for _, channel := range connection.SubContainers {
					require.NotNil(t, channel)
					assert.Equal(t, ChannelContainer, channel.ContainerType)
					assert.Equal(t, tc.expectedChannelContainerSize, len(channel.SubContainers))
					assert.Equal(t, len(tc.expectedChannelChecksums), len(channel.FileChecksumValidations))
					assert.Equal(t, tc.expectedChannelChecksums, channel.FileChecksumValidations)
				}
			}
		})
	}
}
