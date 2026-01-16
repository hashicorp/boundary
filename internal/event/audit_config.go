// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// AuditConfig defines the configuration required for audit events sinks
type AuditConfig struct {
	// FilterOverrides provide an optional a set of overrides for the
	// FilterOperations to be applied to DataClassifications.
	FilterOverrides    AuditFilterOperations `hcl:"-"`
	FilterOverridesHCL map[string]string     `hcl:"audit_filter_overrides"`

	// wrapper to use for audit event crypto operations.
	wrapper wrapping.Wrapper
}

// NewAuditConfig creates a new config starting with the DefaultAuditConfig()
// and applying options. Supported options are: WithWrapper and
// WithFilterOperations.
func NewAuditConfig(opt ...Option) (*AuditConfig, error) {
	const op = "event.NewAuditConfig"
	opts := getOpts(opt...)
	c := DefaultAuditConfig()
	if opts.withAuditWrapper != nil {
		c.wrapper = opts.withAuditWrapper
	}
	if opts.withFilterOperations != nil {
		c.FilterOverrides = opts.withFilterOperations
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: invalid configuration: %w", op, err)
	}
	return c, nil
}

// Validate the AuditConfig
func (ac *AuditConfig) Validate() error {
	const op = "event.(AuditConfig).Validate"

	// validate overrides first so all other checks can assert that they are
	// valid.
	if err := ac.FilterOverrides.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// Note: we don't validate the wrapper here because it may not be set yet.

	return nil
}

// DefaultAuditConfig specifies a default AuditConfig.  The default config will
// redact both sensitive and secret classifications, so by default a wrapper is
// not required.
func DefaultAuditConfig() *AuditConfig {
	return &AuditConfig{
		FilterOverrides: DefaultAuditFilterOperations(),
	}
}
