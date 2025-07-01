// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package configutil

func (c *SharedConfig) Merge(c2 *SharedConfig) *SharedConfig {
	if c2 == nil {
		return c
	}

	result := new(SharedConfig)

	result.Listeners = append(result.Listeners, c.Listeners...)
	result.Listeners = append(result.Listeners, c2.Listeners...)

	result.Entropy = c.Entropy
	if c2.Entropy != nil {
		result.Entropy = c2.Entropy
	}

	result.Seals = append(result.Seals, c.Seals...)
	result.Seals = append(result.Seals, c2.Seals...)

	result.Telemetry = c.Telemetry
	if c2.Telemetry != nil {
		result.Telemetry = c2.Telemetry
	}

	result.DisableMlock = c.DisableMlock
	if c2.DisableMlock {
		result.DisableMlock = c2.DisableMlock
	}

	result.DefaultMaxRequestDuration = c.DefaultMaxRequestDuration
	if c2.DefaultMaxRequestDuration > result.DefaultMaxRequestDuration {
		result.DefaultMaxRequestDuration = c2.DefaultMaxRequestDuration
	}

	result.LogLevel = c.LogLevel
	if c2.LogLevel != "" {
		result.LogLevel = c2.LogLevel
	}

	result.LogFormat = c.LogFormat
	if c2.LogFormat != "" {
		result.LogFormat = c2.LogFormat
	}

	result.PidFile = c.PidFile
	if c2.PidFile != "" {
		result.PidFile = c2.PidFile
	}

	result.ClusterName = c.ClusterName
	if c2.ClusterName != "" {
		result.ClusterName = c2.ClusterName
	}

	return result
}
