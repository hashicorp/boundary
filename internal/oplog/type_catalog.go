package oplog

import (
	"fmt"
	"reflect"

	"github.com/hashicorp/boundary/internal/errors"
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
	const op = "oplog.NewTypeCatalog"
	reg := TypeCatalog{}
	for _, t := range withTypes {
		if t == (Type{}) {
			return nil, errors.NewDeprecated(errors.InvalidParameter, op, "error type is {}")
		}
		if err := reg.Set(t.Interface, t.Name); err != nil {
			return nil, errors.WrapDeprecated(err, op, errors.WithMsg("error setting the type"))
		}
	}
	return &reg, nil
}

// GetTypeName returns the interface's name from the catalog
func (t *TypeCatalog) GetTypeName(i interface{}) (string, error) {
	const op = "oplog.(TypeCatalog).GetTypeName"
	if i == nil {
		return "", errors.NewDeprecated(errors.InvalidParameter, op, "nil interface")
	}
	if reflect.ValueOf(i).Kind() != reflect.Ptr {
		return "", errors.NewDeprecated(errors.InvalidParameter, op, "interface must to be a pointer")
	}
	interfaceType := reflect.TypeOf(i)
	for name, t := range *t {
		if t == interfaceType {
			return name, nil
		}
	}
	return "", errors.NewDeprecated(errors.InvalidParameter, op, fmt.Sprintf("unknown name for interface: %T", i))
}

// Set creates an entry in the catalog for the interface
func (t TypeCatalog) Set(i interface{}, typeName string) error {
	const op = "oplog.(TypeCatalog).Set"
	if i == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "nil interface")
	}
	if reflect.ValueOf(i).Kind() != reflect.Ptr {
		return errors.NewDeprecated(errors.InvalidParameter, op, "interface must to be a pointer")
	}
	if typeName == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing type name")
	}
	t[typeName] = reflect.TypeOf(i)
	return nil
}

// Get retrieves the interface via a name
func (t TypeCatalog) Get(typeName string) (interface{}, error) {
	const op = "oplog.(TypeCatalog).Get"
	if typeName == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing type name")
	}
	if typ, ok := t[typeName]; ok {
		return reflect.New(typ.Elem()).Elem().Addr().Interface(), nil
	}
	return nil, errors.NewDeprecated(errors.KeyNotFound, op, "type name not found")
}
