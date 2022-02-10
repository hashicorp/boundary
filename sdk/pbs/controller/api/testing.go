package api

import (
	"reflect"
	"testing"

	"github.com/hashicorp/eventlogger/filters/encrypt"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// NewEncryptFilter is a copy of event.NewEncryptFilter since importing it would
// case circular deps.  The primary reason for this test func is to make sure
// the proper IgnoreTypes are included for testing.
func NewEncryptFilter(t *testing.T, w wrapping.Wrapper) *encrypt.Filter {
	t.Helper()
	return &encrypt.Filter{
		Wrapper: w,
		IgnoreTypes: []reflect.Type{
			reflect.TypeOf(&fieldmaskpb.FieldMask{}),
		},
	}
}
