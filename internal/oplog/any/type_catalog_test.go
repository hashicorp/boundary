package any

import (
	"testing"

	"github.com/hashicorp/watchtower/internal/oplog/oplog_test"
	"github.com/matryer/is"
)

func Test_TypeCalalog(t *testing.T) {
	t.Parallel()
	is := is.New(t)
	types, err := NewTypeCatalog(
		Type{new(oplog_test.TestUser), "user"},
		Type{new(oplog_test.TestCar), "car"},
		Type{new(oplog_test.TestRental), "rental"},
	)
	is.NoErr(err)

	url, err := GetTypeURL(types, new(oplog_test.TestUser))
	is.NoErr(err)
	is.True(url == "user")

	_, err = GetTypeURL(types, oplog_test.TestUser{})
	is.True(err != nil)

	s := "string"
	_, err = GetTypeURL(types, &s)
	is.True(err != nil)

	_, err = types.Get("unknown")
	is.True(err != nil)

}
