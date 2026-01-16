// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	workerpbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

// ConnectionStatus of the connection's state
type ConnectionStatus string

const (
	StatusAuthorized  ConnectionStatus = "authorized"
	StatusConnected   ConnectionStatus = "connected"
	StatusClosed      ConnectionStatus = "closed"
	StatusUnspecified ConnectionStatus = "unspecified" // Utility state not valid in the DB
)

// String representation of the state's status
func (s ConnectionStatus) String() string {
	return string(s)
}

// ProtoVal returns the enum value corresponding to the state
func (s ConnectionStatus) ProtoVal() workerpbs.CONNECTIONSTATUS {
	switch s {
	case StatusAuthorized:
		return workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED
	case StatusConnected:
		return workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED
	case StatusClosed:
		return workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED
	}
	return workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_UNSPECIFIED
}

// ConnectionStatusFromProtoVal is the reverse of
// ConnectionStatus.ProtoVal.
func ConnectionStatusFromProtoVal(s workerpbs.CONNECTIONSTATUS) ConnectionStatus {
	switch s {
	case workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED:
		return StatusAuthorized
	case workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED:
		return StatusConnected
	case workerpbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED:
		return StatusClosed
	}
	return StatusUnspecified
}

func ConnectionStatusFromString(s string) ConnectionStatus {
	switch s {
	case "authorized":
		return StatusAuthorized
	case "connected":
		return StatusConnected
	case "closed":
		return StatusClosed
	}
	return StatusUnspecified
}
