package oplog

import (
	"reflect"
	"testing"

	"github.com/hashicorp/boundary/internal/oplog/oplog_test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_TypeCatalog provides basic red/green unit tests
func Test_TypeCatalog(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)

	types, err := NewTypeCatalog(
		Type{new(oplog_test.TestUser), "user"},
		Type{new(oplog_test.TestCar), "car"},
		Type{new(oplog_test.TestRental), "rental"},
	)
	require.NoError(err)

	name, err := types.GetTypeName(new(oplog_test.TestUser))
	require.NoError(err)
	assert.Equal(name, "user")

	_, err = types.GetTypeName(oplog_test.TestUser{})
	assert.Error(err)

	s := "string"
	_, err = types.GetTypeName(&s)
	assert.Error(err)

	_, err = types.Get("unknown")
	assert.Error(err)
}

// Test_NewTypeCatalog provides unit tests for NewTypeCatalog
func Test_NewTypeCatalog(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
			Type{new(oplog_test.TestCar), "car"},
			Type{new(oplog_test.TestRental), "rental"},
		)
		require.NoError(err)
		u, err := types.Get("user")
		require.NoError(err)
		assert.Equal(reflect.TypeOf(u), reflect.TypeOf(new(oplog_test.TestUser)))
	})
	t.Run("missing Type.Name", func(t *testing.T) {
		assert := assert.New(t)

		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), ""},
		)
		assert.Nil(types)
		assert.Error(err)
		assert.Equal(err.Error(), "error setting the type: typeName is an empty string for Set (in NewTypeCatalog)")
	})
	t.Run("missing Type.Interface", func(t *testing.T) {
		assert := assert.New(t)

		types, err := NewTypeCatalog(
			Type{nil, ""},
		)
		assert.Nil(types)
		assert.Error(err)
		assert.Equal(err.Error(), "error type is {} (in NewTypeCatalog)")
	})
	t.Run("empty Type", func(t *testing.T) {
		assert := assert.New(t)

		types, err := NewTypeCatalog(
			Type{},
		)
		assert.Nil(types)
		assert.Error(err)
		assert.Equal(err.Error(), "error type is {} (in NewTypeCatalog)")
	})

}

// Test_GetTypeName provides unit tests for GetTypeName
func Test_GetTypeName(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
			Type{new(oplog_test.TestCar), "car"},
		)
		require.NoError(err)

		n, err := types.GetTypeName(new(oplog_test.TestUser))
		require.NoError(err)
		assert.Equal(n, "user")
	})
	t.Run("bad name", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
		)
		require.NoError(err)

		n, err := types.GetTypeName(new(oplog_test.TestCar))
		require.Error(err)
		assert.Equal(n, "")
		assert.Equal(err.Error(), "error unknown name for interface: *oplog_test.TestCar")
	})
	t.Run("nil interface", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
		)
		require.NoError(err)

		n, err := types.GetTypeName(nil)
		require.Error(err)
		assert.Equal(n, "")
		assert.Equal(err.Error(), "error interface parameter is nil for GetTypeName")
	})
}

// Test_Get provides unit tests for Get
func Test_Get(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
			Type{new(oplog_test.TestCar), "car"},
		)
		require.NoError(err)

		u, err := types.Get("user")
		require.NoError(err)
		assert.Equal(reflect.TypeOf(u), reflect.TypeOf(new(oplog_test.TestUser)))
	})
	t.Run("bad name", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
		)
		require.NoError(err)

		n, err := types.Get("car")
		require.Error(err)
		assert.Equal(n, nil)
		assert.Equal(err.Error(), "error typeName is not found for Get")
	})
	t.Run("bad typeName", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		types, err := NewTypeCatalog(
			Type{new(oplog_test.TestUser), "user"},
		)
		require.NoError(err)

		n, err := types.Get("")
		require.Error(err)
		assert.Equal(n, nil)
		assert.Equal(err.Error(), "error typeName is empty string for Get")
	})
}

// Test_Set provides unit tests for Set
func Test_Set(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		types, err := NewTypeCatalog()
		require.NoError(err)
		u := new(oplog_test.TestUser)
		err = types.Set(u, "user")
		require.NoError(err)
		assert.Equal(reflect.TypeOf(u), reflect.TypeOf(new(oplog_test.TestUser)))
	})
	t.Run("bad name", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		types, err := NewTypeCatalog()
		require.NoError(err)
		u := new(oplog_test.TestUser)
		err = types.Set(u, "")
		require.Error(err)
		assert.Equal(err.Error(), "typeName is an empty string for Set")
		assert.Equal(types, &TypeCatalog{})
	})
	t.Run("bad interface", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		types, err := NewTypeCatalog()
		require.NoError(err)
		err = types.Set(nil, "")
		require.Error(err)
		assert.Equal(err.Error(), "error interface parameter is nil for Set")
		assert.Equal(types, &TypeCatalog{})
	})
}
