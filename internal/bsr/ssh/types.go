// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"github.com/hashicorp/boundary/internal/bsr"
)

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

// ChannelSummary encapsulates data for a channel
// SessionProgram can only be one of the following: exec, shell, or subsystem
// SubsystemName is only populated if SessionProgram is subsystem
// ExecApplicationProgram is only populated if Channel Program is subsystem, and can be one of the following:
//
//	scp, rsync, or unknown
type ChannelSummary struct {
	ChannelSummary *bsr.ChannelSummary
	SessionProgram SessionProgram
	SubsystemName  string
	ExecProgram    ExecApplicationProgram
}
