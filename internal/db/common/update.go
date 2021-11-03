// common package contains functions from internal/db which need to be shared
// commonly with other packages that have a cyclic dependency on internal/db
// like internal/oplog.
package common

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
	"gorm.io/gorm"
)

// UpdateFields will create a map[string]interface of the update values to be
// sent to the db.  The map keys will be the field names for the fields to be
// updated.  The caller provided fieldMaskPaths and setToNullPaths must not
// intersect.  fieldMaskPaths and setToNullPaths cannot both be zero len.
func UpdateFields(i interface{}, fieldMaskPaths []string, setToNullPaths []string) (map[string]interface{}, error) {
	const op = "common.UpdateFields"
	if i == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "interface is missing")
	}
	if fieldMaskPaths == nil {
		fieldMaskPaths = []string{}
	}
	if setToNullPaths == nil {
		setToNullPaths = []string{}
	}
	if len(fieldMaskPaths) == 0 && len(setToNullPaths) == 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "both fieldMaskPaths and setToNullPaths are zero len")
	}

	inter, maskPaths, nullPaths, err := Intersection(fieldMaskPaths, setToNullPaths)
	if err != nil {
		return nil, errors.WrapDeprecated(err, op)
	}
	if len(inter) != 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "fieldMashPaths and setToNullPaths cannot intersect")
	}

	updateFields := map[string]interface{}{} // case sensitive update fields to values

	found := map[string]struct{}{} // we need something to keep track of found fields (case insensitive)

	val := reflect.Indirect(reflect.ValueOf(i))
	structTyp := val.Type()
	for i := 0; i < structTyp.NumField(); i++ {
		if f, ok := maskPaths[strings.ToUpper(structTyp.Field(i).Name)]; ok {
			updateFields[f] = val.Field(i).Interface()
			found[strings.ToUpper(f)] = struct{}{}
			continue
		}
		if f, ok := nullPaths[strings.ToUpper(structTyp.Field(i).Name)]; ok {
			updateFields[f] = gorm.Expr("NULL")
			found[strings.ToUpper(f)] = struct{}{}
			continue
		}
		kind := structTyp.Field(i).Type.Kind()
		if kind == reflect.Struct || kind == reflect.Ptr {
			embType := structTyp.Field(i).Type
			// check if the embedded field is exported via CanInterface()
			if val.Field(i).CanInterface() {
				embVal := reflect.Indirect(reflect.ValueOf(val.Field(i).Interface()))
				// if it's a ptr to a struct, then we need a few more bits before proceeding.
				if kind == reflect.Ptr {
					embVal = val.Field(i).Elem()
					if !embVal.IsValid() {
						continue
					}
					embType = embVal.Type()
					if embType.Kind() != reflect.Struct {
						continue
					}
				}
				for embFieldNum := 0; embFieldNum < embType.NumField(); embFieldNum++ {
					if f, ok := maskPaths[strings.ToUpper(embType.Field(embFieldNum).Name)]; ok {
						updateFields[f] = embVal.Field(embFieldNum).Interface()
						found[strings.ToUpper(f)] = struct{}{}
					}
					if f, ok := nullPaths[strings.ToUpper(embType.Field(embFieldNum).Name)]; ok {
						updateFields[f] = gorm.Expr("NULL")
						found[strings.ToUpper(f)] = struct{}{}
					}
				}
				continue
			}
		}
	}

	if missing := findMissingPaths(setToNullPaths, found); len(missing) != 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, fmt.Sprintf("null paths not found in resource: %s", missing))
	}

	if missing := findMissingPaths(fieldMaskPaths, found); len(missing) != 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, fmt.Sprintf("field mask paths not found in resource: %s", missing))
	}

	return updateFields, nil
}

func findMissingPaths(paths []string, foundPaths map[string]struct{}) []string {
	notFound := []string{}
	for _, f := range paths {
		if _, ok := foundPaths[strings.ToUpper(f)]; !ok {
			notFound = append(notFound, f)
		}
	}
	return notFound
}

// Intersection is a case-insensitive search for intersecting values.  Returns
// []string of the Intersection with values in lowercase, and map[string]string
// of the original av and bv, with the key set to uppercase and value set to the
// original
func Intersection(av, bv []string) ([]string, map[string]string, map[string]string, error) {
	const op = "common.Intersection"
	if av == nil {
		return nil, nil, nil, errors.NewDeprecated(errors.InvalidParameter, op, "av is missing")
	}
	if bv == nil {
		return nil, nil, nil, errors.NewDeprecated(errors.InvalidParameter, op, "bv is missing")
	}
	if len(av) == 0 && len(bv) == 0 {
		return []string{}, map[string]string{}, map[string]string{}, nil
	}
	s := []string{}
	ah := map[string]string{}
	bh := map[string]string{}

	for i := 0; i < len(av); i++ {
		ah[strings.ToUpper(av[i])] = av[i]
	}
	for i := 0; i < len(bv); i++ {
		k := strings.ToUpper(bv[i])
		bh[k] = bv[i]
		if _, found := ah[k]; found {
			s = append(s, strings.ToLower(bh[k]))
		}
	}
	return s, ah, bh, nil
}

// BuildUpdatePaths takes a map of field names to field values, field masks,
// fields allowed to be zero value, and returns both a list of field names to
// update and a list of field names that should be set to null.
func BuildUpdatePaths(fieldValues map[string]interface{}, fieldMask []string, allowZeroFields []string) (masks []string, nulls []string) {
	for f, v := range fieldValues {
		if !contains(fieldMask, f) {
			continue
		}
		switch {
		case isZero(v) && !contains(allowZeroFields, f):
			nulls = append(nulls, f)
		default:
			masks = append(masks, f)
		}
	}
	return masks, nulls
}

func contains(ss []string, t string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, t) {
			return true
		}
	}
	return false
}

func isZero(i interface{}) bool {
	return i == nil || reflect.DeepEqual(i, reflect.Zero(reflect.TypeOf(i)).Interface())
}
