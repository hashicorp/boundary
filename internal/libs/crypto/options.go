package crypto

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct {
	withPrefix         string
	withPrk            []byte
	withEd25519        bool
	withBase64Encoding bool
}

func getDefaultOptions() options {
	return options{}
}

// WithPrefix allows an optional prefix to be specified for the data returned
func WithPrefix(prefix string) Option {
	return func(o *options) {
		o.withPrefix = prefix
	}
}

// WithPrk allows an optional PRK (pseudorandom key) to be specified for an
// operation.  If you're using this option with HmacSha256, you might consider
// using HmacSha256WithPrk instead.
func WithPrk(prk []byte) Option {
	return func(o *options) {
		o.withPrk = prk
	}
}

// WithEd25519 allows an optional request to use ed25519 during the operation
func WithEd25519() Option {
	return func(o *options) {
		o.withEd25519 = true
	}
}

// WithBase64Encoding allows an optional request to base64 encode the data returned
func WithBase64Encoding() Option {
	return func(o *options) {
		o.withBase64Encoding = true
	}
}
