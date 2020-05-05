package api

import "github.com/fatih/structs"

func init() {
	structs.DefaultTagName = "json"
}

// Bool returns the given bool as a bool pointer
func Bool(in bool) *bool {
	ret := new(bool)
	*ret = in
	return ret
}

// String returns the given string as a string pointer
func String(in string) *string {
	ret := new(string)
	*ret = in
	return ret
}

// StringOrNil is like String, but the returned pointer will be nil if the
// string is empty
func StringOrNil(in string) *string {
	if in == "" {
		return nil
	}
	return String(in)
}

// Int returns the given int64 as an int64 pointer
func Int(in int64) *int64 {
	ret := new(int64)
	*ret = in
	return ret
}

// IntOrNil is like Int, but the returned pointer will be nil if the integer is
// 0
func IntOrNil(in int64) *int64 {
	if in == 0 {
		return nil
	}
	return Int(in)
}
