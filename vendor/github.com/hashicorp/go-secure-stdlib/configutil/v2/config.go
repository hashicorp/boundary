// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package configutil

import (
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
)

// These two functions are overridden if metricsutil is invoked, but keep this
// module from needing to depend on metricsutil and its various deps otherwise.
// Import the metricsutil module, e.g.
//
// _ "github.com/hashicorp/go-secure-stdlib/metricsutil"
//
// in order to have telemetry be parsed.
var (
	ParseTelemetry    = func(*ast.ObjectList) (interface{}, error) { return nil, nil }
	SanitizeTelemetry = func(interface{}) map[string]interface{} { return nil }
)

// SharedConfig contains some shared values
type SharedConfig struct {
	EntSharedConfig

	Listeners []*listenerutil.ListenerConfig `hcl:"-"`

	Seals   []*KMS   `hcl:"-"`
	Entropy *Entropy `hcl:"-"`

	DisableMlock    bool        `hcl:"-"`
	DisableMlockRaw interface{} `hcl:"disable_mlock"`

	Telemetry interface{} `hcl:"telemetry"`

	DefaultMaxRequestDuration    time.Duration `hcl:"-"`
	DefaultMaxRequestDurationRaw interface{}   `hcl:"default_max_request_duration"`

	// LogFormat specifies the log format. Valid values are "standard" and
	// "json". The values are case-insenstive. If no log format is specified,
	// then standard format will be used.
	LogFormat string `hcl:"log_format"`
	LogLevel  string `hcl:"log_level"`

	PidFile string `hcl:"pid_file"`

	ClusterName string `hcl:"cluster_name"`
}

// LoadConfigFile loads the configuration from the given file.
// Supported options:
//   - WithMaxKmsBlocks
//   - WithListenerOptions
func LoadConfigFile(path string, opt ...Option) (*SharedConfig, error) {
	// Read the file
	d, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(string(d), opt...)
}

// LoadConfigKMSes loads KMS configuration from the provided path.
// Supported options:
//   - WithMaxKmsBlocks
func LoadConfigKMSes(path string, opt ...Option) ([]*KMS, error) {
	// Read the file
	d, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKMSes(string(d), opt...)
}

// ParseConfig parses the string d as a SharedConfig struct.
// Supported options:
//   - WithMaxKmsBlocks
//   - WithListenerOptions
func ParseConfig(d string, opt ...Option) (*SharedConfig, error) {
	// Parse!
	obj, err := hcl.Parse(d)
	if err != nil {
		return nil, err
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Start building the result
	var result SharedConfig
	if err := hcl.DecodeObject(&result, obj); err != nil {
		return nil, err
	}

	if result.DefaultMaxRequestDurationRaw != nil {
		if result.DefaultMaxRequestDuration, err = parseutil.ParseDurationSecond(result.DefaultMaxRequestDurationRaw); err != nil {
			return nil, err
		}
		result.DefaultMaxRequestDurationRaw = nil
	}

	if result.DisableMlockRaw != nil {
		if result.DisableMlock, err = parseutil.ParseBool(result.DisableMlockRaw); err != nil {
			return nil, err
		}
		result.DisableMlockRaw = nil
	}

	result.ClusterName, err = parseutil.ParsePath(result.ClusterName)
	if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
		return nil, fmt.Errorf("error parsing cluster name: %w", err)
	}

	list, ok := obj.Node.(*ast.ObjectList)
	if !ok {
		return nil, fmt.Errorf("error parsing: file doesn't contain a root object")
	}

	if result.Seals, err = filterKMSes(list, opts.withMaxKmsBlocks); err != nil {
		return nil, fmt.Errorf("error parsing kms information: %w", err)
	}

	if o := list.Filter("entropy"); len(o.Items) > 0 {
		if err := ParseEntropy(&result, o, "entropy"); err != nil {
			return nil, fmt.Errorf("error parsing 'entropy': %w", err)
		}
	}

	if o := list.Filter("listener"); len(o.Items) > 0 {
		l, err := listenerutil.ParseListeners(o, opts.withListenerOptions...)
		if err != nil {
			return nil, fmt.Errorf("error parsing 'listener': %w", err)
		}
		result.Listeners = l
	}

	if o := list.Filter("telemetry"); len(o.Items) > 0 {
		t, err := ParseTelemetry(o)
		if err != nil {
			return nil, fmt.Errorf("error parsing 'telemetry': %w", err)
		}
		result.Telemetry = t
	}

	entConfig := &(result.EntSharedConfig)
	if err := entConfig.ParseConfig(list); err != nil {
		return nil, fmt.Errorf("error parsing enterprise config: %w", err)
	}

	return &result, nil
}

// Sanitized returns a copy of the config with all values that are considered
// sensitive stripped. It also strips all `*Raw` values that are mainly
// used for parsing.
//
// Specifically, the fields that this method strips are:
// - KMS.Config
// - Telemetry.CirconusAPIToken
func (c *SharedConfig) Sanitized() map[string]interface{} {
	if c == nil {
		return nil
	}

	result := map[string]interface{}{
		"disable_mlock": c.DisableMlock,

		"default_max_request_duration": c.DefaultMaxRequestDuration,

		"log_level":  c.LogLevel,
		"log_format": c.LogFormat,

		"pid_file": c.PidFile,

		"cluster_name": c.ClusterName,
	}

	// Sanitize listeners
	if len(c.Listeners) != 0 {
		var sanitizedListeners []interface{}
		for _, ln := range c.Listeners {
			cleanLn := map[string]interface{}{
				"type":   ln.Type,
				"config": ln.RawConfig,
			}
			sanitizedListeners = append(sanitizedListeners, cleanLn)
		}
		result["listeners"] = sanitizedListeners
	}

	// Sanitize seals stanza
	if len(c.Seals) != 0 {
		var sanitizedSeals []interface{}
		for _, s := range c.Seals {
			cleanSeal := map[string]interface{}{
				"type":     s.Type,
				"disabled": s.Disabled,
			}
			sanitizedSeals = append(sanitizedSeals, cleanSeal)
		}
		result["seals"] = sanitizedSeals
	}

	// Sanitize telemetry stanza
	if c.Telemetry != nil {
		result["telemetry"] = SanitizeTelemetry(c.Telemetry)
	}

	return result
}
