// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

// sysVersion defines the version of sys events
const sysVersion = "v0.1"

type sysEvent struct {
	Id      Id             `json:"-"`
	Version string         `json:"version"`
	Op      Op             `json:"op,omitempty"`
	Data    map[string]any `json:"data"`
}

// EventType is required for all event types by the eventlogger broker
func (e *sysEvent) EventType() string { return string(SystemType) }
