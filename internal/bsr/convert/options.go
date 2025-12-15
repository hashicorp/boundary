// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package convert

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withChannelId string
	withMinWidth  uint32
	withMinHeight uint32
}

func getDefaultOptions() options {
	return options{}
}

// WithChannelId provides and option to specify the channelId
func WithChannelId(id string) Option {
	return func(o *options) {
		o.withChannelId = id
	}
}

// WithMinWidth can be used to set a minimum width for playback.
func WithMinWidth(w uint32) Option {
	return func(o *options) {
		o.withMinWidth = w
	}
}

// WithMinHeight can be used to set a minimum height for playback.
func WithMinHeight(h uint32) Option {
	return func(o *options) {
		o.withMinHeight = h
	}
}
