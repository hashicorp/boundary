// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"fmt"
	"io"
	"math"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note, we cannot validate the allocation of the rolling buffer
// because these tests are utilizing MemFiles and not SyncingFiles.
// MemFile does not implement a rolling buffer.
// This test validates that the minimum buffer size for each file
// type is accurate.
func TestValidateBufferSize(t *testing.T) {
	protocol := bsr.TestRegisterSummaryAllocFunc(t)

	ctx := context.Background()
	ts := time.Date(1995, time.March, 3, 12, 12, 12, 999999999, time.UTC)

	sessionId, err := db.NewPublicId(ctx, globals.SessionRecordingPrefix)
	require.NoError(t, err)

	connectionId, err := db.NewPublicId(ctx, globals.ConnectionRecordingPrefix)
	require.NoError(t, err)

	channelId, err := db.NewPublicId(ctx, globals.ChannelRecordingPrefix)
	require.NoError(t, err)

	containerName := fmt.Sprintf("%s.bsr", sessionId)
	connectionName := fmt.Sprintf("%s.connection", connectionId)
	channelName := fmt.Sprintf("%s.channel", channelId)

	var writer storage.Writer
	fs := &fstest.MemFS{}
	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), sessionId)
	require.NoError(t, err)

	// setup session container
	session, err := bsr.NewSession(ctx, bsr.TestSessionRecordingMeta(sessionId, protocol), bsr.TestSessionMeta(sessionId), fs, keys, bsr.WithSupportsMultiplex(true))
	require.NoError(t, err)
	require.NoError(t, session.EncodeSummary(ctx, &bsr.BaseSessionSummary{
		Id:              sessionId,
		ConnectionCount: math.MaxUint64,
		StartTime:       ts,
		EndTime:         ts,
		Errors: bsr.SummaryError{
			Message: "",
		},
	}))

	// setup connection container
	connection, err := session.NewConnection(ctx, &bsr.ConnectionRecordingMeta{
		Id: connectionId,
	})
	require.NoError(t, err)
	require.NoError(t, connection.EncodeSummary(ctx, &bsr.BaseConnectionSummary{
		Id:           connectionId,
		ChannelCount: math.MaxUint64,
		BytesUp:      math.MaxUint64,
		BytesDown:    math.MaxUint64,
		StartTime:    ts,
		EndTime:      ts,
		Errors: bsr.SummaryError{
			Message: "",
		},
	}))
	// create connection inbound request writer
	writer, err = connection.NewRequestsWriter(ctx, bsr.Inbound)
	require.NoError(t, err)
	closer, ok := writer.(io.Closer)
	require.True(t, ok)
	require.NoError(t, closer.Close())
	// create connection outbound request writer
	writer, err = connection.NewRequestsWriter(ctx, bsr.Outbound)
	require.NoError(t, err)
	closer, ok = writer.(io.Closer)
	require.True(t, ok)
	require.NoError(t, closer.Close())

	// create channel container
	channel, err := connection.NewChannel(ctx, &bsr.ChannelRecordingMeta{
		Id:   channelId,
		Type: "session",
	})
	require.NoError(t, err)
	require.NoError(t, channel.EncodeSummary(ctx, &ChannelSummary{
		ChannelSummary: &bsr.BaseChannelSummary{
			Id:                    channelId,
			ConnectionRecordingId: connectionId,
			BytesUp:               math.MaxUint64,
			BytesDown:             math.MaxUint64,
			StartTime:             ts,
			EndTime:               ts,
			ChannelType:           "session",
		},
		SessionProgram:        NotApplicable,
		SubsystemName:         "",
		ExecProgram:           ExecApplicationProgramNotApplicable,
		FileTransferDirection: FileTransferNotApplicable,
		OpenFailure: &OpenChannelError{
			Reason:  math.MaxUint32,
			Message: "",
		},
	}))
	// create channel inbound request writer
	writer, err = channel.NewRequestsWriter(ctx, bsr.Inbound)
	require.NoError(t, err)
	closer, ok = writer.(io.Closer)
	require.True(t, ok)
	require.NoError(t, closer.Close())
	// create channel outbound request writer
	writer, err = channel.NewRequestsWriter(ctx, bsr.Outbound)
	require.NoError(t, err)
	closer, ok = writer.(io.Closer)
	require.True(t, ok)
	require.NoError(t, closer.Close())
	// create channel inbound message writer
	writer, err = channel.NewMessagesWriter(ctx, bsr.Inbound)
	require.NoError(t, err)
	closer, ok = writer.(io.Closer)
	require.True(t, ok)
	require.NoError(t, closer.Close())
	// create channel outbound message writer
	writer, err = channel.NewMessagesWriter(ctx, bsr.Outbound)
	require.NoError(t, err)
	closer, ok = writer.(io.Closer)
	require.True(t, ok)
	require.NoError(t, closer.Close())

	// close containers
	require.NoError(t, channel.Close(ctx))
	require.NoError(t, connection.Close(ctx))
	require.NoError(t, session.Close(ctx))

	// validate CHECKSUM.sig buffer size
	// this should always be 88 bytes for
	// all container types
	actualChecksumSignatureSize := fs.Containers[containerName].Files["SHA256SUM.sig"].Buf.Len()
	expectedChecksumSignatureBufferSize, err := bsr.SessionContainer.ChecksumSignatureBufferSize()
	require.NoError(t, err)
	assert.EqualValues(t, expectedChecksumSignatureBufferSize, actualChecksumSignatureSize)

	// validate CHECKSUM buffer size
	// this should always be 320 bytes
	// for all container types. This
	// ensures a single line can be written:
	// hash + empty space + file name
	expectedChecksumBufferSize, err := bsr.SessionContainer.ChecksumBufferSize()
	require.NoError(t, err)
	assert.EqualValues(t, expectedChecksumBufferSize, len("dc8ce2c42553ce510197c99efe21d89d6229feb4b49170511f49965f2e3cf1a3 ")+255)

	cases := []struct {
		name                       string
		containerType              bsr.ContainerType
		actualJournalSize          int
		actualRecordingMetaSize    int
		actualRecordingSummarySize int
	}{
		{
			name:                       "session",
			containerType:              bsr.SessionContainer,
			actualJournalSize:          fs.Containers[containerName].Files[".journal"].Buf.Len(),
			actualRecordingMetaSize:    len(fmt.Sprintf("connection: %s.connection", connectionId)),
			actualRecordingSummarySize: fs.Containers[containerName].Files["session-recording-summary.json"].Buf.Len(),
		},
		{
			name:                       "connection",
			containerType:              bsr.ConnectionContainer,
			actualJournalSize:          fs.Containers[containerName].Sub[connectionName].Files[".journal"].Buf.Len(),
			actualRecordingMetaSize:    len(fmt.Sprintf("channel: %s.channel", channelId)),
			actualRecordingSummarySize: fs.Containers[containerName].Sub[connectionName].Files["connection-recording-summary.json"].Buf.Len(),
		},
		{
			name:                       "channel",
			containerType:              bsr.ChannelContainer,
			actualJournalSize:          fs.Containers[containerName].Sub[connectionName].Sub[channelName].Files[".journal"].Buf.Len(),
			actualRecordingMetaSize:    fs.Containers[containerName].Sub[connectionName].Sub[channelName].Files["channel-recording.meta"].Buf.Len(),
			actualRecordingSummarySize: fs.Containers[containerName].Sub[connectionName].Sub[channelName].Files["channel-recording-summary.json"].Buf.Len(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectedJournalBufferSize, err := tc.containerType.JournalBufferSize()
			require.NoError(t, err)
			assert.EqualValues(t, expectedJournalBufferSize, tc.actualJournalSize)

			expectedRecordingMetaBufferSize, err := tc.containerType.RecordingMetaBufferSize()
			require.NoError(t, err)
			assert.EqualValues(t, expectedRecordingMetaBufferSize, tc.actualRecordingMetaSize)

			expectedRecordingSummaryBufferSize, err := tc.containerType.RecordingSummaryBufferSize()
			require.NoError(t, err)
			assert.EqualValues(t, expectedRecordingSummaryBufferSize, tc.actualRecordingSummarySize)
		})
	}
}
