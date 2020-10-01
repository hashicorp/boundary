package perms

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
	withUserId              string
	withAccountId           string
	withSkipFinalValidation bool
}

func getDefaultOptions() options {
	return options{}
}

// WithUserId provides a user ID to be used for any templating in grant strings
func WithUserId(userId string) Option {
	return func(o *options) {
		o.withUserId = userId
	}
}

// WithAccountId provides an account ID to be used for any templating in grant
// strings
func WithAccountId(accountId string) Option {
	return func(o *options) {
		o.withAccountId = accountId
	}
}

// WithSkipFinalValidation allows skipping the validity step where we ensure we
// can run a resource described by the grant successfully through the ACL check
func WithSkipFinalValidation(skipFinalValidation bool) Option {
	return func(o *options) {
		o.withSkipFinalValidation = skipFinalValidation
	}
}
