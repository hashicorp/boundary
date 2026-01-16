// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/kr/pretty"
	"github.com/posener/complete"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// FlagExample is an interface which declares an example value.
type FlagExample interface {
	Example() string
}

// FlagVisibility is an interface which declares whether a flag should be
// hidden from help and completions. This is usually used for deprecations
// on "internal-only" flags.
type FlagVisibility interface {
	Hidden() bool
}

// FlagBool is an interface which boolean flags implement.
type FlagBool interface {
	IsBoolFlag() bool
}

// -- BoolVar  and boolValue
type BoolVar struct {
	Name       string
	Aliases    []string
	Usage      string
	Default    bool
	Hidden     bool
	EnvVar     string
	Target     *bool
	Completion complete.Predictor
}

func (f *FlagSet) BoolVar(i *BoolVar) {
	def := i.Default
	if v, exist := os.LookupEnv(i.EnvVar); exist {
		if b, err := strconv.ParseBool(v); err == nil {
			def = b
		}
	}

	f.VarFlag(&VarFlag{
		Name:       i.Name,
		Aliases:    i.Aliases,
		Usage:      i.Usage,
		Default:    strconv.FormatBool(i.Default),
		EnvVar:     i.EnvVar,
		Value:      newBoolValue(def, i.Target, i.Hidden),
		Completion: i.Completion,
	})
}

type boolValue struct {
	hidden bool
	target *bool
}

func newBoolValue(def bool, target *bool, hidden bool) *boolValue {
	*target = def

	return &boolValue{
		hidden: hidden,
		target: target,
	}
}

func (b *boolValue) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}

	*b.target = v
	return nil
}

func (b *boolValue) Get() any         { return *b.target }
func (b *boolValue) String() string   { return strconv.FormatBool(*b.target) }
func (b *boolValue) Example() string  { return "" }
func (b *boolValue) Hidden() bool     { return b.hidden }
func (b *boolValue) IsBoolFlag() bool { return true }

// -- Int64Var and int64Value
type Int64Var struct {
	Name       string
	Aliases    []string
	Usage      string
	Default    int64
	Hidden     bool
	EnvVar     string
	Target     *int64
	Completion complete.Predictor
}

func (f *FlagSet) Int64Var(i *Int64Var) {
	initial := i.Default
	if v, exist := os.LookupEnv(i.EnvVar); exist {
		if i, err := strconv.ParseInt(v, 0, 64); err == nil {
			initial = i
		}
	}

	def := ""
	if i.Default != 0 {
		def = strconv.FormatInt(int64(i.Default), 10)
	}

	f.VarFlag(&VarFlag{
		Name:       i.Name,
		Aliases:    i.Aliases,
		Usage:      i.Usage,
		Default:    def,
		EnvVar:     i.EnvVar,
		Value:      newInt64Value(initial, i.Target, i.Hidden),
		Completion: i.Completion,
	})
}

type int64Value struct {
	hidden bool
	target *int64
}

func newInt64Value(def int64, target *int64, hidden bool) *int64Value {
	*target = def
	return &int64Value{
		hidden: hidden,
		target: target,
	}
}

func (i *int64Value) Set(s string) error {
	v, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return err
	}

	*i.target = v
	return nil
}

func (i *int64Value) Get() any        { return int64(*i.target) }
func (i *int64Value) String() string  { return strconv.FormatInt(int64(*i.target), 10) }
func (i *int64Value) Example() string { return "int" }
func (i *int64Value) Hidden() bool    { return i.hidden }

// -- Uint64Var and uint64Value
type Uint64Var struct {
	Name       string
	Aliases    []string
	Usage      string
	Default    uint64
	Hidden     bool
	EnvVar     string
	Target     *uint64
	Completion complete.Predictor
}

func (f *FlagSet) Uint64Var(i *Uint64Var) {
	initial := i.Default
	if v, exist := os.LookupEnv(i.EnvVar); exist {
		if i, err := strconv.ParseUint(v, 0, 64); err == nil {
			initial = i
		}
	}

	def := ""
	if i.Default != 0 {
		strconv.FormatUint(i.Default, 10)
	}

	f.VarFlag(&VarFlag{
		Name:       i.Name,
		Aliases:    i.Aliases,
		Usage:      i.Usage,
		Default:    def,
		EnvVar:     i.EnvVar,
		Value:      newUint64Value(initial, i.Target, i.Hidden),
		Completion: i.Completion,
	})
}

type uint64Value struct {
	hidden bool
	target *uint64
}

func newUint64Value(def uint64, target *uint64, hidden bool) *uint64Value {
	*target = def
	return &uint64Value{
		hidden: hidden,
		target: target,
	}
}

func (i *uint64Value) Set(s string) error {
	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return err
	}

	*i.target = v
	return nil
}

func (i *uint64Value) Get() any        { return uint64(*i.target) }
func (i *uint64Value) String() string  { return strconv.FormatUint(uint64(*i.target), 10) }
func (i *uint64Value) Example() string { return "uint" }
func (i *uint64Value) Hidden() bool    { return i.hidden }

// -- Uint16Var and uint16Value
type Uint16Var struct {
	Name       string
	Aliases    []string
	Usage      string
	Default    uint16
	Hidden     bool
	EnvVar     string
	Target     *uint16
	Completion complete.Predictor
}

func (f *FlagSet) Uint16Var(i *Uint16Var) {
	initial := i.Default
	if v, exist := os.LookupEnv(i.EnvVar); exist {
		if i, err := strconv.ParseUint(v, 0, 16); err == nil {
			initial = uint16(i)
		}
	}

	def := ""
	if i.Default != 0 {
		strconv.FormatUint(uint64(i.Default), 10)
	}

	f.VarFlag(&VarFlag{
		Name:       i.Name,
		Aliases:    i.Aliases,
		Usage:      i.Usage,
		Default:    def,
		EnvVar:     i.EnvVar,
		Value:      newUint16Value(initial, i.Target, i.Hidden),
		Completion: i.Completion,
	})
}

type uint16Value struct {
	hidden bool
	target *uint16
}

func newUint16Value(def uint16, target *uint16, hidden bool) *uint16Value {
	*target = def
	return &uint16Value{
		hidden: hidden,
		target: target,
	}
}

func (i *uint16Value) Set(s string) error {
	v, err := strconv.ParseUint(s, 0, 16)
	if err != nil {
		return err
	}

	*i.target = uint16(v)
	return nil
}

func (i *uint16Value) Get() any        { return uint64(*i.target) }
func (i *uint16Value) String() string  { return strconv.FormatUint(uint64(*i.target), 10) }
func (i *uint16Value) Example() string { return "uint" }
func (i *uint16Value) Hidden() bool    { return i.hidden }

// -- StringVar and stringValue
type StringVar struct {
	Name       string
	Aliases    []string
	Usage      string
	Default    string
	Hidden     bool
	EnvVar     string
	Target     *string
	Completion complete.Predictor
}

func (f *FlagSet) StringVar(i *StringVar) {
	initial := i.Default
	if v, exist := os.LookupEnv(i.EnvVar); exist {
		initial = v
	}

	def := ""
	if i.Default != "" {
		def = i.Default
	}

	f.VarFlag(&VarFlag{
		Name:       i.Name,
		Aliases:    i.Aliases,
		Usage:      i.Usage,
		Default:    def,
		EnvVar:     i.EnvVar,
		Value:      newStringValue(initial, i.Target, i.Hidden),
		Completion: i.Completion,
	})
}

type stringValue struct {
	hidden bool
	target *string
}

func newStringValue(def string, target *string, hidden bool) *stringValue {
	*target = def
	return &stringValue{
		hidden: hidden,
		target: target,
	}
}

func (s *stringValue) Set(val string) error {
	*s.target = val
	return nil
}

func (s *stringValue) Get() any        { return *s.target }
func (s *stringValue) String() string  { return *s.target }
func (s *stringValue) Example() string { return "string" }
func (s *stringValue) Hidden() bool    { return s.hidden }

// -- Float64Var and float64Value
type Float64Var struct {
	Name       string
	Aliases    []string
	Usage      string
	Default    float64
	Hidden     bool
	EnvVar     string
	Target     *float64
	Completion complete.Predictor
}

func (f *FlagSet) Float64Var(i *Float64Var) {
	initial := i.Default
	if v, exist := os.LookupEnv(i.EnvVar); exist {
		if i, err := strconv.ParseFloat(v, 64); err == nil {
			initial = i
		}
	}

	def := ""
	if i.Default != 0 {
		def = strconv.FormatFloat(i.Default, 'e', -1, 64)
	}

	f.VarFlag(&VarFlag{
		Name:       i.Name,
		Aliases:    i.Aliases,
		Usage:      i.Usage,
		Default:    def,
		EnvVar:     i.EnvVar,
		Value:      newFloat64Value(initial, i.Target, i.Hidden),
		Completion: i.Completion,
	})
}

type float64Value struct {
	hidden bool
	target *float64
}

func newFloat64Value(def float64, target *float64, hidden bool) *float64Value {
	*target = def
	return &float64Value{
		hidden: hidden,
		target: target,
	}
}

func (f *float64Value) Set(s string) error {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}

	*f.target = v
	return nil
}

func (f *float64Value) Get() any        { return float64(*f.target) }
func (f *float64Value) String() string  { return strconv.FormatFloat(float64(*f.target), 'g', -1, 64) }
func (f *float64Value) Example() string { return "float" }
func (f *float64Value) Hidden() bool    { return f.hidden }

// -- DurationVar and durationValue
type DurationVar struct {
	Name       string
	Aliases    []string
	Usage      string
	Default    time.Duration
	Hidden     bool
	EnvVar     string
	Target     *time.Duration
	Completion complete.Predictor
}

func (f *FlagSet) DurationVar(i *DurationVar) {
	initial := i.Default
	if v, exist := os.LookupEnv(i.EnvVar); exist {
		if d, err := time.ParseDuration(appendDurationSuffix(v)); err == nil {
			initial = d
		}
	}

	def := ""
	if i.Default != 0 {
		def = i.Default.String()
	}

	f.VarFlag(&VarFlag{
		Name:       i.Name,
		Aliases:    i.Aliases,
		Usage:      i.Usage,
		Default:    def,
		EnvVar:     i.EnvVar,
		Value:      newDurationValue(initial, i.Target, i.Hidden),
		Completion: i.Completion,
	})
}

type durationValue struct {
	hidden bool
	target *time.Duration
}

func newDurationValue(def time.Duration, target *time.Duration, hidden bool) *durationValue {
	*target = def
	return &durationValue{
		hidden: hidden,
		target: target,
	}
}

func (d *durationValue) Set(s string) error {
	// Maintain bc for people specifying "system" as the value.
	if s == "system" {
		s = "-1"
	}

	v, err := time.ParseDuration(appendDurationSuffix(s))
	if err != nil {
		return err
	}
	*d.target = v
	return nil
}

func (d *durationValue) Get() any        { return time.Duration(*d.target) }
func (d *durationValue) String() string  { return (*d.target).String() }
func (d *durationValue) Example() string { return "duration" }
func (d *durationValue) Hidden() bool    { return d.hidden }

// appendDurationSuffix is used as a backwards-compat tool for assuming users
// meant "seconds" when they do not provide a suffixed duration value.
func appendDurationSuffix(s string) string {
	if strings.HasSuffix(s, "s") || strings.HasSuffix(s, "m") || strings.HasSuffix(s, "h") {
		return s
	}
	return s + "s"
}

// StringSliceVar reads in parameters from the same flag into a string array.
// Setting NullCheck enables the following behavior: the function will be run
// whenever a "null" is seen in the input to determine whether or not it is
// allowed (and erroring if not); and even if allowed generally, the flag will
// ensure that "null" is the only value passed.
type StringSliceVar struct {
	Name       string
	Aliases    []string
	Usage      string
	Default    []string
	Hidden     bool
	EnvVar     string
	Target     *[]string
	NullCheck  func() bool
	Completion complete.Predictor
}

func (f *FlagSet) StringSliceVar(i *StringSliceVar) {
	initial := i.Default
	if v, exist := os.LookupEnv(i.EnvVar); exist {
		parts := strings.Split(v, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		initial = parts
	}

	def := ""
	if i.Default != nil {
		def = strings.Join(i.Default, ",")
	}

	f.VarFlag(&VarFlag{
		Name:       i.Name,
		Aliases:    i.Aliases,
		Usage:      i.Usage,
		Default:    def,
		EnvVar:     i.EnvVar,
		Value:      newStringSliceValue(initial, i.Target, i.Hidden, i.NullCheck),
		Completion: i.Completion,
	})
}

type stringSliceValue struct {
	hidden    bool
	nullCheck func() bool
	target    *[]string
}

func newStringSliceValue(def []string, target *[]string, hidden bool, nullCheck func() bool) *stringSliceValue {
	*target = def
	return &stringSliceValue{
		hidden:    hidden,
		nullCheck: nullCheck,
		target:    target,
	}
}

func (s *stringSliceValue) Set(val string) error {
	trimmedVal := strings.TrimSpace(val)
	// Don't enable this behavior if nullCheck is not defined
	if s.nullCheck != nil {
		// If we got null in, go through some checks
		if trimmedVal == "null" {
			// Ensure null is allowed here
			if !s.nullCheck() {
				return fmt.Errorf(`"null" is not an allowed value`)
			}
			// If we have at least one value already and it's not "null" then
			// error; we don't check if _all_ are "null" since presumably this
			// function prevents there being more values than just "null" if
			// that's specified
			if len(*s.target) > 0 && (*s.target)[0] != "null" {
				return fmt.Errorf(`"null" cannot be combined with other values`)
			}
			// Set the target to only contain "null" and return
			*s.target = []string{"null"}
			return nil
		} else if len(*s.target) == 1 && (*s.target)[0] == "null" {
			// Something came in that isn't "null" but we already have "null"
			return fmt.Errorf(`"null" cannot be combined with other values`)
		}
	}
	// Append in all other cases, or if we didn't error above or return just
	// "null"
	*s.target = append(*s.target, strings.TrimSpace(val))
	return nil
}

func (s *stringSliceValue) Get() any        { return *s.target }
func (s *stringSliceValue) String() string  { return strings.Join(*s.target, ",") }
func (s *stringSliceValue) Example() string { return "string" }
func (s *stringSliceValue) Hidden() bool    { return s.hidden }

// -- StringMapVar and stringMapValue
type StringMapVar struct {
	Name       string
	Aliases    []string
	Usage      string
	Default    map[string]string
	Hidden     bool
	Target     *map[string]string
	Completion complete.Predictor
}

func (f *FlagSet) StringMapVar(i *StringMapVar) {
	def := ""
	if i.Default != nil {
		def = mapToKV(i.Default)
	}

	f.VarFlag(&VarFlag{
		Name:       i.Name,
		Aliases:    i.Aliases,
		Usage:      i.Usage,
		Default:    def,
		Value:      newStringMapValue(i.Default, i.Target, i.Hidden),
		Completion: i.Completion,
	})
}

type stringMapValue struct {
	hidden bool
	target *map[string]string
}

func newStringMapValue(def map[string]string, target *map[string]string, hidden bool) *stringMapValue {
	*target = def
	return &stringMapValue{
		hidden: hidden,
		target: target,
	}
}

func (s *stringMapValue) Set(val string) error {
	idx := strings.Index(val, "=")
	if idx == -1 {
		return fmt.Errorf("missing = in KV pair: %q", val)
	}

	if *s.target == nil {
		*s.target = make(map[string]string)
	}

	k, v := val[0:idx], val[idx+1:]
	(*s.target)[k] = v
	return nil
}

func (s *stringMapValue) Get() any        { return *s.target }
func (s *stringMapValue) String() string  { return mapToKV(*s.target) }
func (s *stringMapValue) Example() string { return "key=value" }
func (s *stringMapValue) Hidden() bool    { return s.hidden }

func mapToKV(m map[string]string) string {
	list := make([]string, 0, len(m))
	for k := range m {
		list = append(list, k)
	}
	sort.Strings(list)

	for i, k := range list {
		list[i] = k + "=" + m[k]
	}

	return strings.Join(list, ",")
}

// StringSliceMapVar maps a key string to a slice of string values.
// This is useful for cases such as modifying Worker tags, which can have
// multiple values associated per key.
// Setting NullCheck to return true enables the string input value "null"
// to be accepted without throwing an error. This is useful for add/set/remove
// patterns where we want to enable "set null".
type StringSliceMapVar struct {
	Name       string
	Aliases    []string
	Usage      string
	Default    map[string][]string
	Hidden     bool
	Target     *map[string][]string
	NullCheck  func() bool
	Completion complete.Predictor
}

func (f *FlagSet) StringSliceMapVar(i *StringSliceMapVar) {
	f.VarFlag(&VarFlag{
		Name:       i.Name,
		Aliases:    i.Aliases,
		Usage:      i.Usage,
		Value:      newStringSliceMapValue(i.Default, i.Target, i.NullCheck, i.Hidden),
		Completion: i.Completion,
	})
}

type stringSliceMapValue struct {
	hidden    bool
	target    *map[string][]string
	nullCheck func() bool
	isNull    bool
}

func newStringSliceMapValue(def map[string][]string, target *map[string][]string, nullCheck func() bool, hidden bool) *stringSliceMapValue {
	*target = def
	return &stringSliceMapValue{
		hidden:    hidden,
		target:    target,
		nullCheck: nullCheck,
		isNull:    false,
	}
}

func (s *stringSliceMapValue) Set(val string) error {
	kv := strings.TrimSpace(val)

	// Don't enable this behavior if nullCheck is not defined.
	if s.nullCheck != nil {
		if kv == "null" {
			if !s.nullCheck() {
				return fmt.Errorf(`"null" is not an allowed value`)
			}
			// Ensure "null" cannot be entered as a consecutive entry in a chain of valid entries
			if s.isNull == true || len(*s.target) > 0 {
				return fmt.Errorf(`"null" cannot be combined with other values`)
			}
			// Set target to nil and return
			if kv == "null" {
				*s.target = map[string][]string{"null": nil}
				s.isNull = true
				return nil
			}
		} else if s.isNull == true {
			// Ensure consecutive "non-null" entries cannot be entered after a "null"
			return fmt.Errorf(`"null" cannot be combined with other values`)
		}
	}
	// Return a better error message if "null" is not enabled
	if kv == "null" {
		return fmt.Errorf(`"null" is not an allowed value`)
	}

	if *s.target == nil {
		*s.target = make(map[string][]string)
	}
	split := strings.SplitN(kv, "=", 2)
	if len(split) != 2 {
		return fmt.Errorf("missing = in KV pair: %q", val)
	}

	// trim space, check proto, and assign to map
	key := strings.TrimSpace(split[0])
	if !protoIdentifierRegex.Match([]byte(key)) {
		return fmt.Errorf("key %q is invalid", key)
	}

	vals := strings.Split(split[1], ",")
	for i, v := range vals {
		vals[i] = strings.TrimSpace(v)
		if !protoIdentifierRegex.Match([]byte(vals[i])) {
			return fmt.Errorf("value %q is invalid", vals[i])
		}
	}
	for _, v := range vals {
		(*s.target)[key] = append((*s.target)[key], v)
	}

	return nil
}

func sliceMapToKV(m map[string][]string) string {
	list := make([]string, 0, len(m))
	for k, vals := range m {
		vv := strings.Join(vals, ",")
		list = append(list, k+"="+vv)
	}
	return strings.Join(list, ", ")
}

func (s *stringSliceMapValue) Get() any        { return *s.target }
func (s *stringSliceMapValue) String() string  { return sliceMapToKV(*s.target) }
func (s *stringSliceMapValue) Example() string { return "key1=val-a, key2=val-b,val-c" }
func (s *stringSliceMapValue) Hidden() bool    { return s.hidden }

// -- VarFlag
type VarFlag struct {
	Name       string
	Aliases    []string
	Usage      string
	Default    string
	EnvVar     string
	Value      flag.Value
	Completion complete.Predictor
}

func (f *FlagSet) VarFlag(i *VarFlag) {
	// If the flag is marked as hidden, just add it to the set and return to
	// avoid unnecessary computations here. We do not want to add completions or
	// generate help output for hidden flags.
	if v, ok := i.Value.(FlagVisibility); ok && v.Hidden() {
		f.Var(i.Value, i.Name, "")
		return
	}

	// Calculate the full usage
	usage := i.Usage

	if len(i.Aliases) > 0 {
		sentence := make([]string, len(i.Aliases))
		for i, a := range i.Aliases {
			sentence[i] = fmt.Sprintf(`"-%s"`, a)
		}

		aliases := ""
		switch len(sentence) {
		case 0:
			// impossible...
		case 1:
			aliases = sentence[0]
		case 2:
			aliases = sentence[0] + " and " + sentence[1]
		default:
			sentence[len(sentence)-1] = "and " + sentence[len(sentence)-1]
			aliases = strings.Join(sentence, ", ")
		}

		usage += fmt.Sprintf(" This is aliased as %s.", aliases)
	}

	if i.Default != "" {
		usage += fmt.Sprintf(" The default is %s.", i.Default)
	}

	if i.EnvVar != "" {
		usage += fmt.Sprintf(" This can also be specified via the %s "+
			"environment variable.", i.EnvVar)
	}

	// Add aliases to the main set
	for _, a := range i.Aliases {
		f.mainSet.Var(i.Value, a, "")
	}

	f.Var(i.Value, i.Name, usage)
	f.completions["-"+i.Name] = i.Completion
}

// Var is a lower-level API for adding something to the flags. It should be used
// with caution, since it bypasses all validation. Consider VarFlag instead.
func (f *FlagSet) Var(value flag.Value, name, usage string) {
	f.mainSet.Var(value, name, usage)
	f.flagSet.Var(value, name, usage)
}

// CombinationSliceVar uses a wrapped value to allow storing values from
// different flags in one slice. This is useful if you need ordering to be
// maintained across flags. It does not currently support env vars.
//
// If KvSplit is set true, each value will be split on the first = into Key and
// Value parts so that validation can happen at parsing time. If you don't want
// this kind of behavior, simply combine them, or set KvSplit to false.
//
// If KeyOnlyAllowed is true then it is valid to parse an input with only a key
// segment and no value.
//
// If KeyDelimiter is non-nil (along with KvSplit being true), the string will
// be used to split the key. Otherwise, the Keys will be a single-element slice
// containing the full value.
//
// If ProtoCompat is true, the key will be validated against proto3 syntax
// requirements for identifiers. If the string is split via KeyDelimiter, each
// segment will be evaluated independently.
type CombinationSliceVar struct {
	Name           string
	Aliases        []string
	Usage          string
	Hidden         bool
	Target         *[]CombinedSliceFlagValue
	Completion     complete.Predictor
	KvSplit        bool
	KeyOnlyAllowed bool
	KeyDelimiter   *string
	ProtoCompatKey bool
}

func (f *FlagSet) CombinationSliceVar(i *CombinationSliceVar) {
	f.VarFlag(&VarFlag{
		Name:       i.Name,
		Aliases:    i.Aliases,
		Usage:      i.Usage,
		Value:      newCombinedSliceValue(i.Name, i.Target, i.Hidden, i.KvSplit, i.KeyOnlyAllowed, i.KeyDelimiter, i.ProtoCompatKey),
		Completion: i.Completion,
	})
}

// CombinedSliceValue holds the raw value (as a string) and the name of the flag
// that added it.
type CombinedSliceFlagValue struct {
	Name  string
	Keys  []string
	Value *wrapperspb.StringValue
}

type combinedSliceValue struct {
	name           string
	hidden         bool
	kvSplit        bool
	keyOnlyAllowed bool
	keyDelimiter   *string
	protoCompatKey bool
	target         *[]CombinedSliceFlagValue
}

func newCombinedSliceValue(name string, target *[]CombinedSliceFlagValue, hidden, kvSplit, keyOnlyAllowed bool, keyDelimiter *string, protoCompatKey bool) *combinedSliceValue {
	return &combinedSliceValue{
		name:           name,
		hidden:         hidden,
		kvSplit:        kvSplit,
		keyDelimiter:   keyDelimiter,
		keyOnlyAllowed: keyOnlyAllowed,
		protoCompatKey: protoCompatKey,
		target:         target,
	}
}

var protoIdentifierRegex = regexp.MustCompile("^[a-zA-Z][A-Za-z0-9_]*$")

func (c *combinedSliceValue) Set(val string) error {
	ret := CombinedSliceFlagValue{
		Name:  c.name,
		Value: wrapperspb.String(strings.TrimSpace(val)),
	}

	if c.kvSplit {
		kv := strings.SplitN(ret.Value.GetValue(), "=", 2)
		switch len(kv) {
		case 0:
			// This shouldn't happen
			return fmt.Errorf("unexpected length of string after splitting")
		case 1:
			if !c.keyOnlyAllowed {
				return fmt.Errorf("key-only value provided but not supported for this flag")
			}
			ret.Keys = []string{kv[0]}
			ret.Value = nil
		default:
			ret.Keys = []string{kv[0]}
			if c.keyDelimiter != nil {
				ret.Keys = strings.Split(kv[0], *c.keyDelimiter)
			}
			ret.Value = wrapperspb.String(strings.TrimSpace(kv[1]))
		}
	}

	// Trim keys
	for i, key := range ret.Keys {
		ret.Keys[i] = strings.TrimSpace(key)
	}

	if c.protoCompatKey {
		for _, key := range ret.Keys {
			if !protoIdentifierRegex.Match([]byte(key)) {
				return fmt.Errorf("key segment %q is invalid", key)
			}
		}
	}

	if ret.Value != nil {
		pathParsedValue, err := parseutil.ParsePath(ret.Value.GetValue())
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			return fmt.Errorf("error checking if value is a path: %w", err)
		}
		// This will either be the round-tripped value or the substituted value
		ret.Value = wrapperspb.String(pathParsedValue)
	}

	*c.target = append(*c.target, ret)
	return nil
}

func (c *combinedSliceValue) Get() any        { return *c.target }
func (c *combinedSliceValue) String() string  { return pretty.Sprint(*c.target) }
func (c *combinedSliceValue) Example() string { return "" }
func (c *combinedSliceValue) Hidden() bool    { return c.hidden }
