package oplog

import (
	"errors"
	fmt "fmt"
	"reflect"
)

// TypeCatalog is an abstraction for dealing with oplog data and their underlying types
type TypeCatalog map[string]reflect.Type

// Type provides the ability to associate an interface with a Type.URL which
// will decouple the interface from it's reflection type string, so you can
// refactor the type name without breaking the catalog
type Type struct {
	// Interface of the type
	Interface interface{}
	// URL for the interface
	URL string
}

// NewTypeCatalog creates a catalog with the types you pass in
func NewTypeCatalog(withTypes ...Type) (*TypeCatalog, error) {
	reg := TypeCatalog{}
	for _, t := range withTypes {
		if err := reg.Set(t.Interface, t.URL); err != nil {
			return nil, fmt.Errorf("error setting the type: %w", err)
		}
	}
	return &reg, nil
}

// GetURL returns the interface's URL from the catalog
func GetTypeURL(catalog *TypeCatalog, i interface{}) (string, error) {
	if reflect.ValueOf(i).Kind() != reflect.Ptr {
		return "", errors.New("TypeCatalog.Set() argument must to be a pointer")
	}
	interfaceType := reflect.TypeOf(i)
	for url, t := range *catalog {
		if t == interfaceType {
			return url, nil
		}
	}
	return "", fmt.Errorf("Unknown URL for interface: %T", i)
}

// Set creates an entry in the catalog for the interface
func (t TypeCatalog) Set(i interface{}, typeURL string) error {
	if reflect.ValueOf(i).Kind() != reflect.Ptr {
		return errors.New("TypeCatalog.Set() argument must to be a pointer")
	}
	t[typeURL] = reflect.TypeOf(i)
	return nil
}

// Get retrieves the interface via a name
func (t TypeCatalog) Get(typeURL string) (interface{}, error) {
	if typ, ok := t[typeURL]; ok {
		return reflect.New(typ.Elem()).Elem().Addr().Interface(), nil
	}
	return nil, errors.New("TypeCatalog.Get: no one")
}
