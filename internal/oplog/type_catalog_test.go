package oplog

import (
	"reflect"
	"testing"

	"github.com/hashicorp/watchtower/internal/oplog/oplog_test"
	"gotest.tools/assert"
)

// Test_TypeCatalog provides basic red/green unit tests
func Test_TypeCatalog(t *testing.T) {
	t.Parallel()

	types, err := NewTypeCatalog(
		Type{new(oplog_test.TestUser), "user"},
		Type{new(oplog_test.TestCar), "car"},
		Type{new(oplog_test.TestRental), "rental"},
	)
	assert.NilError(t, err)

	name, err := types.GetTypeName(new(oplog_test.TestUser))
	assert.NilError(t, err)
	assert.Assert(t, name == "user")

	_, err = types.GetTypeName(oplog_test.TestUser{})
	assert.Assert(t, err != nil)

	s := "string"
	_, err = types.GetTypeName(&s)
	assert.Assert(t, err != nil)

	_, err = types.Get("unknown")
	assert.Assert(t, err != nil)

}

// Test_NewTypeCatalog provides unit tests for NewTypeCatalog
func Test_NewTypeCatalog(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
			Type{new(oplog_test.TestCar), "car"},
			Type{new(oplog_test.TestRental), "rental"},
		)
		assert.NilError(t, err)
		u, err := types.Get("user")
		assert.NilError(t, err)
		assert.Equal(t, reflect.TypeOf(u), reflect.TypeOf(new(oplog_test.TestUser)))
	})
	t.Run("missing Type.Name", func(t *testing.T) {
		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), ""},
		)
		assert.Check(t, types == nil)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error setting the type: typeName is an empty string for Set (in NewTypeCatalog)")
	})
	t.Run("missing Type.Interface", func(t *testing.T) {
		types, err := NewTypeCatalog(
			Type{nil, ""},
		)
		assert.Check(t, types == nil)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error type is {} (in NewTypeCatalog)")
	})
	t.Run("empty Type", func(t *testing.T) {
		types, err := NewTypeCatalog(
			Type{},
		)
		assert.Check(t, types == nil)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error type is {} (in NewTypeCatalog)")
	})

}

// Test_GetTypeName provides unit tests for GetTypeName
func Test_GetTypeName(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
			Type{new(oplog_test.TestCar), "car"},
		)
		assert.NilError(t, err)

		n, err := types.GetTypeName(new(oplog_test.TestUser))
		assert.NilError(t, err)
		assert.Equal(t, n, "user")
	})
	t.Run("bad name", func(t *testing.T) {
		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
		)
		assert.NilError(t, err)

		n, err := types.GetTypeName(new(oplog_test.TestCar))
		assert.Check(t, err != nil)
		assert.Equal(t, n, "")
		assert.Equal(t, err.Error(), "error unknown name for interface: *oplog_test.TestCar")
	})
	t.Run("nil interface", func(t *testing.T) {
		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
		)
		assert.NilError(t, err)

		n, err := types.GetTypeName(nil)
		assert.Check(t, err != nil)
		assert.Equal(t, n, "")
		assert.Equal(t, err.Error(), "error interface parameter is nil for GetTypeName")
	})
}

// Test_Get provides unit tests for Get
func Test_Get(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
			Type{new(oplog_test.TestCar), "car"},
		)
		assert.NilError(t, err)

		u, err := types.Get("user")
		assert.NilError(t, err)
		assert.Equal(t, reflect.TypeOf(u), reflect.TypeOf(new(oplog_test.TestUser)))
	})
	t.Run("bad name", func(t *testing.T) {
		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
		)
		assert.NilError(t, err)

		n, err := types.Get("car")
		assert.Check(t, err != nil)
		assert.Equal(t, n, nil)
		assert.Equal(t, err.Error(), "error typeName is not found for Get")
	})
	t.Run("bad typeName", func(t *testing.T) {
		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
		)
		assert.NilError(t, err)

		n, err := types.Get("")
		assert.Check(t, err != nil)
		assert.Equal(t, n, nil)
		assert.Equal(t, err.Error(), "error typeName is empty string for Get")
	})
}

// Test_Set provides unit tests for Set
func Test_Set(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		types, err := NewTypeCatalog()
		assert.NilError(t, err)
		u := new(oplog_test.TestUser)
		err = types.Set(u, "user")
		assert.NilError(t, err)
		assert.Equal(t, reflect.TypeOf(u), reflect.TypeOf(new(oplog_test.TestUser)))
	})
	t.Run("bad name", func(t *testing.T) {
		types, err := NewTypeCatalog()
		assert.NilError(t, err)
		u := new(oplog_test.TestUser)
		err = types.Set(u, "")
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "typeName is an empty string for Set")
		assert.Assert(t, reflect.DeepEqual(types, &TypeCatalog{}))
	})
	t.Run("bad interface", func(t *testing.T) {
		types, err := NewTypeCatalog()
		assert.NilError(t, err)
		err = types.Set(nil, "")
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error interface parameter is nil for Set")
		assert.Assert(t, reflect.DeepEqual(types, &TypeCatalog{}))
	})
}
