package proxy

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct{}

func getDefaultOptions() options {
	return options{}
}
