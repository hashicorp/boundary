package targets

import (
	"github.com/hashicorp/boundary/internal/target"
	"google.golang.org/protobuf/types/known/structpb"
)

func getOpts(opt ...option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type option func(*options)

// options = how options are represented
type options struct {
	withTarget target.Target
	withStruct *structpb.Struct
}

func getDefaultOptions() options {
	return options{
		withTarget: nil,
		withStruct: nil,
	}
}

// withTarget provides an option to provide a target.Target.
func withTarget(t target.Target) option {
	return func(o *options) {
		o.withTarget = t
	}
}

// withStruct provides an option to provide a structpb.Struct.
func withStruct(s *structpb.Struct) option {
	return func(o *options) {
		o.withStruct = s
	}
}
