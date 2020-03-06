package any

import (
	"errors"
	"fmt"
	"reflect"
)

// TypeCatalog is an abstraction for dealing with oplog data and their underlying types
type TypeCatalog map[string]reflect.Type

// NewTypeCatalog creates a catalog with the types you pass in
func NewTypeCatalog(withTypes ...interface{}) (*TypeCatalog, error) {
	reg := TypeCatalog{}
	for _, t := range withTypes {
		if err := reg.Set(t); err != nil {
			return nil, err
		}
	}
	// reg.Set(new(iam_store.MSP))
	return &reg, nil
}

// GetTypeName returns the interfaces name
func GetTypeName(i interface{}) (string, error) {
	if reflect.ValueOf(i).Kind() != reflect.Ptr {
		return "", errors.New("TypeCatalog.Set() argument must to be a pointer")
	}
	return reflect.TypeOf(i).String(), nil
}

// Set creates an entry in the catalog for the interface
func (t TypeCatalog) Set(i interface{}) error {
	if reflect.ValueOf(i).Kind() != reflect.Ptr {
		return errors.New("TypeCatalog.Set() argument must to be a pointer")
	}
	t[reflect.TypeOf(i).String()] = reflect.TypeOf(i)
	return nil
}

// Get retrieves the interface via a name
func (t TypeCatalog) Get(name string) (interface{}, error) {
	if typ, ok := t[name]; ok {
		return reflect.New(typ.Elem()).Elem().Addr().Interface(), nil
	}
	return nil, fmt.Errorf("TypeCatalog.Get: no one")
}
