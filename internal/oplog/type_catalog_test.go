package oplog

import (
	"testing"

	"github.com/hashicorp/watchtower/internal/oplog/oplog_test"
	"gotest.tools/assert"
)

func Test_TypeCalalog(t *testing.T) {
	t.Parallel()
	types, err := NewTypeCatalog(
		Type{new(oplog_test.TestUser), "user"},
		Type{new(oplog_test.TestCar), "car"},
		Type{new(oplog_test.TestRental), "rental"},
	)
	assert.NilError(t, err)

	url, err := GetTypeURL(types, new(oplog_test.TestUser))
	assert.NilError(t, err)
	assert.Assert(t, url == "user")

	_, err = GetTypeURL(types, oplog_test.TestUser{})
	assert.Assert(t, err != nil)

	s := "string"
	_, err = GetTypeURL(types, &s)
	assert.Assert(t, err != nil)

	_, err = types.Get("unknown")
	assert.Assert(t, err != nil)

}
