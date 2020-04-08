package oplog

import (
	"errors"
	fmt "fmt"
	"reflect"
)

// TypeCatalog is an abstraction for dealing with oplog data and their underlying types
type TypeCatalog map[string]reflect.Type

// Type provides the ability to associate an interface with a Type.Name which
// will decouple the interface from it's reflection type string, so you can
// refactor the type name without breaking the catalog
type Type struct {
	// Interface of the type
	Interface interface{}
	// Name for the interface
	Name string
}

// NewTypeCatalog creates a catalog with the types you pass in
func NewTypeCatalog(withTypes ...Type) (*TypeCatalog, error) {
	reg := TypeCatalog{}
	for _, t := range withTypes {
		if t == (Type{}) {
			return nil, errors.New("error type is {} (in NewTypeCatalog)")

		}
		if err := reg.Set(t.Interface, t.Name); err != nil {
			return nil, fmt.Errorf("error setting the type: %w (in NewTypeCatalog)", err)
		}
	}
	return &reg, nil
}

// GetTypeName returns the interface's name from the catalog
func (t *TypeCatalog) GetTypeName(i interface{}) (string, error) {
	if i == nil {
		return "", errors.New("error interface parameter is nil for GetTypeName")
	}
	if reflect.ValueOf(i).Kind() != reflect.Ptr {
		return "", errors.New("error interface parameter must to be a pointer for GetTypeName")
	}
	interfaceType := reflect.TypeOf(i)
	for name, t := range *t {
		if t == interfaceType {
			return name, nil
		}
	}
	return "", fmt.Errorf("error unknown name for interface: %T", i)
}

// Set creates an entry in the catalog for the interface
func (t TypeCatalog) Set(i interface{}, typeName string) error {
	if i == nil {
		return errors.New("error interface parameter is nil for Set")
	}
	if reflect.ValueOf(i).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for Set")
	}
	if typeName == "" {
		return errors.New("typeName is an empty string for Set")
	}
	t[typeName] = reflect.TypeOf(i)
	return nil
}

// Get retrieves the interface via a name
func (t TypeCatalog) Get(typeName string) (interface{}, error) {
	if typeName == "" {
		return nil, errors.New("error typeName is empty string for Get")
	}
	if typ, ok := t[typeName]; ok {
		return reflect.New(typ.Elem()).Elem().Addr().Interface(), nil
	}
	return nil, errors.New("error typeName is not found for Get")
}
