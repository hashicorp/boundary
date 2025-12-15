// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"golang.org/x/crypto/ssh"
)

func init() {
	if err := bsr.RegisterSummaryAllocFunc(Protocol, bsr.ChannelContainer, allocChannelSummary); err != nil {
		panic(err)
	}

	if err := bsr.RegisterSummaryAllocFunc(Protocol, bsr.SessionContainer, bsr.AllocSessionSummary); err != nil {
		panic(err)
	}

	if err := bsr.RegisterSummaryAllocFunc(Protocol, bsr.ConnectionContainer, bsr.AllocConnectionSummary); err != nil {
		panic(err)
	}
}

// SessionProgram identifies the program running on this channel
// as outlined in https://www.rfc-editor.org/rfc/rfc4254.html#section-6.5 :
//
//	Once the session has been set up, a program is started at the remote
//	end.  The program can be a shell, an application program, or a
//	subsystem with a host-independent name.  Only one of these requests
//	can succeed per channel.
//
// SessionProgram is only valid when the channel type is 'session'
type SessionProgram string

// SessionPrograms
// If the channel type is not of type session, then NotApplicable is expected
// If the session program is not exec, shell, or subsystem, then None is used
const (
	NotApplicable SessionProgram = "not applicable"
	None          SessionProgram = "none"
	Exec          SessionProgram = "exec"
	Shell         SessionProgram = "shell"
	Subsystem     SessionProgram = "subsystem"
)

// ValidSessionProgram checks if a given SessionProgram is valid.
func ValidSessionProgram(d SessionProgram) bool {
	switch d {
	case Exec, Shell, Subsystem, NotApplicable:
		return true
	}
	return false
}

// ExecApplicationProgram identifies what program was run with exec
// Currently, only Scp and Rsync are recognized to identify file transfers
type ExecApplicationProgram string

// ExecApplicationPrograms
const (
	ExecApplicationProgramNotApplicable ExecApplicationProgram = "not applicable"
	Unknown                             ExecApplicationProgram = "unknown"
	Scp                                 ExecApplicationProgram = "scp"
	Rsync                               ExecApplicationProgram = "rsync"
)

// ValidExecApplicationProgram checks if a given ExecApplicationProgram is valid.
func ValidExecApplicationProgram(d ExecApplicationProgram) bool {
	switch d {
	case Scp, Rsync, Unknown:
		return true
	}
	return false
}

// FileTransferDirection indicates the direction of a file transfer.
type FileTransferDirection string

// Valid file transfer directions.
const (
	FileTransferNotApplicable FileTransferDirection = "not applicable"
	FileTransferUpload        FileTransferDirection = "upload"
	FileTransferDownload      FileTransferDirection = "download"
)

// OpenChannelError provides details if a channel was rejected.
// This will contain details from the SSH_MSG_CHANNEL_OPEN_FAILURE request
// that rejected the channel.
// See: https://www.rfc-editor.org/rfc/rfc4254#section-5.1
type OpenChannelError ssh.OpenChannelError

// ChannelSummary encapsulates data for a channel
// SessionProgram can only be one of the following: exec, shell, or subsystem
// SubsystemName is only populated if SessionProgram is subsystem
// ExecApplicationProgram is only populated if Channel Program is subsystem, and can be one of the following:
//
//	scp, rsync, or unknown
//
// OpenFailure will be nil if the Channel was successfully opened.
type ChannelSummary struct {
	ChannelSummary        *bsr.BaseChannelSummary
	SessionProgram        SessionProgram
	SubsystemName         string
	ExecProgram           ExecApplicationProgram
	FileTransferDirection FileTransferDirection
	OpenFailure           *OpenChannelError `json:",omitempty"`
}

// GetId returns the Id of the container.
func (c *ChannelSummary) GetId() string {
	return c.ChannelSummary.Id
}

// GetId returns the Id of the container.
func (c *ChannelSummary) GetConnectionRecordingId() string {
	return c.ChannelSummary.ConnectionRecordingId
}

// GetStartTime returns the start time using a monotonic clock.
func (c *ChannelSummary) GetStartTime() time.Time {
	return c.ChannelSummary.StartTime
}

// GetEndTime returns the end time using a monotonic clock.
func (c *ChannelSummary) GetEndTime() time.Time {
	return c.ChannelSummary.EndTime
}

// GetBytesUp returns upload bytes.
func (c *ChannelSummary) GetBytesUp() uint64 {
	return c.ChannelSummary.BytesUp
}

// GetBytesDown returns download bytes.
func (c *ChannelSummary) GetBytesDown() uint64 {
	return c.ChannelSummary.BytesDown
}

// GetChannelType the type of summary channel.
func (c *ChannelSummary) GetChannelType() string {
	return c.ChannelSummary.ChannelType
}

func allocChannelSummary(_ context.Context) bsr.Summary {
	return &ChannelSummary{}
}
