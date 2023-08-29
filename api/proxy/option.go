package proxy

// GetOpts iterates the inbound Options and returns a struct and any errors
func GetOpts(opt ...Option) (*Options, error) {
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

// Options contains various options. The values are exported since the options
// are parsed in various other packages.
type Options struct {
	WithListenAddress string
}

// Option is a function that takes in an options struct and sets values or
// returns an error
type Option func(*Options) error

func getDefaultOptions() *Options {
	return &Options{
		WithListenAddress: "127.0.0.1",
	}
}

// WithListenAddress allows overriding a default address to listen on, in ip:port format
func WithListenAddress(with string) Option {
	return func(o *Options) error {
		o.WithListenAddress = with
		return nil
	}
}
