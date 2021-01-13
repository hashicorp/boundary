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
		assert.Equal("oplog.NewTypeCatalog: error setting the type: oplog.(TypeCatalog).Set: missing type name: parameter violation: error #100", err.Error())
	})
	t.Run("missing Type.Interface", func(t *testing.T) {
		assert := assert.New(t)

		types, err := NewTypeCatalog(
			Type{nil, ""},
		)
		assert.Nil(types)
		assert.Error(err)
		assert.Equal("oplog.NewTypeCatalog: error type is {}: parameter violation: error #100", err.Error())
	})
	t.Run("empty Type", func(t *testing.T) {
		assert := assert.New(t)

		types, err := NewTypeCatalog(
			Type{},
		)
		assert.Nil(types)
		assert.Error(err)
		assert.Equal("oplog.NewTypeCatalog: error type is {}: parameter violation: error #100", err.Error())
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
		assert.Equal("oplog.(TypeCatalog).GetTypeName: unknown name for interface: *oplog_test.TestCar: parameter violation: error #100", err.Error())
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
		assert.Equal("oplog.(TypeCatalog).GetTypeName: nil interface: parameter violation: error #100", err.Error())
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
		assert.Equal("oplog.(TypeCatalog).Get: type name not found: integrity violation: error #105", err.Error())
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
		assert.Equal("oplog.(TypeCatalog).Get: missing type name: parameter violation: error #100", err.Error())
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
		assert.Equal("oplog.(TypeCatalog).Set: missing type name: parameter violation: error #100", err.Error())
		assert.Equal(types, &TypeCatalog{})
	})
	t.Run("bad interface", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		types, err := NewTypeCatalog()
		require.NoError(err)
		err = types.Set(nil, "")
		require.Error(err)
		assert.Equal("oplog.(TypeCatalog).Set: nil interface: parameter violation: error #100", err.Error())
		assert.Equal(types, &TypeCatalog{})
	})
}
