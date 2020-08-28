package auth

import "github.com/hashicorp/boundary/internal/kms"

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
	withScopeId string
	withPin     string
	withUserId  string
	withKms     *kms.Kms
}

func getDefaultOptions() options {
	return options{
		withScopeId: "",
		withUserId:  "",
	}
}

func WithScopeId(id string) Option {
	return func(o *options) {
		o.withScopeId = id
	}
}

func WithPin(pin string) Option {
	return func(o *options) {
		o.withPin = pin
	}
}

func WithUserId(id string) Option {
	return func(o *options) {
		o.withUserId = id
	}
}

func WithKms(kms *kms.Kms) Option {
	return func(o *options) {
		o.withKms = kms
	}
}
