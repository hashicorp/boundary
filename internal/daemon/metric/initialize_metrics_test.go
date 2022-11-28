package metric

import (
	"testing"

	"github.com/hashicorp/boundary/internal/gen/testing/protooptions"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// As is, this test will currently fail if the services and methods in the protooptions
// package are changed. Please use temporary testcases to manually debug.
func Test_AppendServicesAndMethods(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		pkg      protoreflect.FileDescriptor
		expected map[string][]string
	}{
		{
			name:     "basic",
			pkg:      protooptions.File_testing_options_v1_service_proto,
			expected: map[string][]string{"testing.options.v1.TestService": {"TestMethod"}},
		},
	}
	for _, tc := range cases {
		m := make(map[string][]string, 0)
		appendServicesAndMethods(m, tc.pkg)
		assert.Equal(t, tc.expected, m)
	}
}
