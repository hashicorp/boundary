// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package credential

import (
	"github.com/hashicorp/boundary/internal/util/template"
)

// GetOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) (*options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(opts); err != nil {
			return nil, err
		}
	}
	return opts, nil
}

// Option - how Options are passed as arguments.
type Option func(*options) error

// options = how options are represented
type options struct {
	WithTemplateData template.Data
}

func getDefaultOptions() *options {
	return &options{}
}

// WithTemplateData provides a way to pass in template information
func WithTemplateData(with template.Data) Option {
	return func(o *options) error {
		o.WithTemplateData = with
		return nil
	}
}
