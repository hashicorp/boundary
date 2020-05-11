package static

import "github.com/hashicorp/watchtower/internal/host/static/store"

type Host struct {
	*store.Host
	tableName string `gorm:"-"`
}

func NewHost(opt ...Option) *Host {
	return nil
}

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
	withPublicId    string
	withName        string
	withDescription string
}

func getDefaultOptions() options {
	return options{
		withPublicId:    "",
		withDescription: "",
		withName:        "",
	}
}

// WithPublicId provides an optional public id
func WithPublicId(id string) Option {
	return func(o *options) {
		o.withPublicId = id
	}
}

// WithDescription provides an optional description
func WithDescription(desc string) Option {
	return func(o *options) {
		o.withDescription = desc
	}
}

// WithName provides an option to search by a friendly name
func WithName(name string) Option {
	return func(o *options) {
		o.withName = name
	}
}
