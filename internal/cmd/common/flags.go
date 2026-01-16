// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/posener/complete"
)

func PopulateCommonFlags(c *base.Command, f *base.FlagSet, resourceType string, flagNames map[string][]string, command string) {
	for _, name := range flagNames[command] {
		switch name {
		case "scope-id":
			f.StringVar(&base.StringVar{
				Name:       "scope-id",
				Target:     &c.FlagScopeId,
				EnvVar:     "BOUNDARY_SCOPE_ID",
				Default:    scope.Global.String(),
				Completion: complete.PredictAnything,
				Usage:      `Scope in which to make the request.`,
			})
		case "scope-name":
			f.StringVar(&base.StringVar{
				Name:       "scope-name",
				Target:     &c.FlagScopeName,
				EnvVar:     "BOUNDARY_SCOPE_NAME",
				Completion: complete.PredictAnything,
				Usage:      `Scope in which to make the request, identified by name.`,
			})
		case "plugin-id":
			f.StringVar(&base.StringVar{
				Name:       "plugin-id",
				Target:     &c.FlagPluginId,
				Completion: complete.PredictAnything,
				Usage:      `ID of a plugin being referenced in the request.`,
			})
		case "plugin-name":
			f.StringVar(&base.StringVar{
				Name:       "plugin-name",
				Target:     &c.FlagPluginName,
				Completion: complete.PredictAnything,
				Usage:      `Name of a plugin being referenced in the request.`,
			})
		case "id":
			f.StringVar(&base.StringVar{
				Name:    "id",
				Target:  &c.FlagId,
				Default: c.FlagId,
				Usage:   fmt.Sprintf("ID of the %s on which to operate.", resourceType),
			})
		case "name":
			f.StringVar(&base.StringVar{
				Name:   "name",
				Target: &c.FlagName,
				Usage:  fmt.Sprintf("Name to set on the %s.", resourceType),
			})
		case "description":
			f.StringVar(&base.StringVar{
				Name:   "description",
				Target: &c.FlagDescription,
				Usage:  fmt.Sprintf("Description to set on the %s.", resourceType),
			})
		case "version":
			f.Int64Var(&base.Int64Var{
				Name:   "version",
				Target: &c.FlagVersion,
				Usage:  fmt.Sprintf("The version of the %s against which to perform an update operation. If not specified, the command will perform a check-and-set automatically.", resourceType),
			})
		case "auth-method-id":
			f.StringVar(&base.StringVar{
				Name:   "auth-method-id",
				EnvVar: "BOUNDARY_AUTH_METHOD_ID",
				Target: &c.FlagAuthMethodId,
				Usage:  "The auth-method resource to use for the operation.",
			})
		case "host-catalog-id":
			f.StringVar(&base.StringVar{
				Name:   "host-catalog-id",
				EnvVar: "BOUNDARY_HOST_CATALOG_ID",
				Target: &c.FlagHostCatalogId,
				Usage:  "The host-catalog resource to use for the operation.",
			})
		case "credential-store-id":
			f.StringVar(&base.StringVar{
				Name:   "credential-store-id",
				EnvVar: "BOUNDARY_CREDENTIAL_STORE_ID",
				Target: &c.FlagCredentialStoreId,
				Usage:  "The credential-store resource to use for the operation.",
			})
		case "recursive":
			f.BoolVar(&base.BoolVar{
				Name:   "recursive",
				Target: &c.FlagRecursive,
				Usage:  "If set, the list operation will be applied recursively into child scopes, if supported by the type.",
			})
		}
	}
	if command == "list" {
		for _, name := range flagNames[command] {
			switch name {
			case "filter":
				f.StringVar(&base.StringVar{
					Name:   "filter",
					Target: &c.FlagFilter,
					Usage:  "If set, the list operation will be filtered before being returned. The filter operates against each item in the list. Using single quotes is recommended as filters contain double quotes. See https://www.boundaryproject.io/docs/concepts/filtering/resource-listing for details.",
				})
			}
		}
	}
}

type CombinedSliceFlagValuePopulationInput struct {
	// FlagSet is the flag set to add vars to
	FlagSet *base.FlagSet

	// FlagNames is the set of flag names
	FlagNames []string

	// FullPopulationFlag is the string var to set if a fully-specified map is
	// supplied, e.g. "attributes"
	FullPopulationFlag *string

	// FullPopulationInputName is the name of the flag when setting a
	// fully-specified map; also used for generating help texts
	FullPopulationInputName string

	// PiecewisePopulationFlag is the var that is built up via the combination
	// method, e.g. "attr", "string-attr", etc.
	PiecewisePopulationFlag *[]base.CombinedSliceFlagValue

	// PiecewisePopulationInputName is the base name of the flag when using the
	// combination method, e.g. "attr" will be used to build "string-attr"; also
	// used for generating help texts
	PiecewisePopulationInputBaseName string

	// If ProtoCompat is true, the key will be validated against proto3 syntax
	// requirements for identifiers. If the string is split via KeyDelimiter, each
	// segment will be evaluated independently.
	PiecewiseNoProtoCompat bool
}

func PopulateCombinedSliceFlagValue(input CombinedSliceFlagValuePopulationInput) {
	keyDelimiter := "."
	for _, name := range input.FlagNames {
		switch name {
		case input.FullPopulationInputName:
			input.FlagSet.StringVar(&base.StringVar{
				Name:   input.FullPopulationInputName,
				Target: input.FullPopulationFlag,
				Usage: fmt.Sprintf(
					"A JSON map value to use as the entirety of the request's %s map. "+
						"Usually this will be sourced from a file via \"file://\" syntax. "+
						"Is exclusive with the other %s flags.",
					input.FullPopulationInputName,
					input.PiecewisePopulationInputBaseName,
				),
			})
		case input.PiecewisePopulationInputBaseName:
			input.FlagSet.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           input.PiecewisePopulationInputBaseName,
				Target:         input.PiecewisePopulationFlag,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: !input.PiecewiseNoProtoCompat,
				KeyOnlyAllowed: true,
				Usage: fmt.Sprintf(
					"A key=value pair to add to the request's %s map. "+
						"This can also be a key value only which will set a JSON null as the value. "+
						"If a value is provided, the type is automatically inferred. Use -string-%s, -bool-%s, or -num-%s if the type needs to be overridden. "+
						"Can be specified multiple times. "+
						"Supports sourcing values from files via \"file://\" and env vars via \"env://\".",
					input.FullPopulationInputName,
					input.PiecewisePopulationInputBaseName,
					input.PiecewisePopulationInputBaseName,
					input.PiecewisePopulationInputBaseName,
				),
			})
		case "string-" + input.PiecewisePopulationInputBaseName:
			input.FlagSet.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "string-" + input.PiecewisePopulationInputBaseName,
				Target:         input.PiecewisePopulationFlag,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage: fmt.Sprintf(
					"A key=value string value to add to the request's %s map. "+
						"Can be specified multiple times. "+
						"Supports sourcing values from files via \"file://\" and env vars via \"env://\"`.",
					input.FullPopulationInputName,
				),
			})
		case "bool-" + input.PiecewisePopulationInputBaseName:
			input.FlagSet.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "bool-" + input.PiecewisePopulationInputBaseName,
				Target:         input.PiecewisePopulationFlag,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage: fmt.Sprintf(
					"A key=value bool value to add to the request's %s map. "+
						"Can be specified multiple times. "+
						"Supports sourcing values from files via \"file://\" and env vars via \"env://\"`.",
					input.FullPopulationInputName,
				),
			})
		case "num-" + input.PiecewisePopulationInputBaseName:
			input.FlagSet.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "num-" + input.PiecewisePopulationInputBaseName,
				Target:         input.PiecewisePopulationFlag,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage: fmt.Sprintf(
					"A key=value numeric value to add to the request's %s map. "+
						"Can be specified multiple times. "+
						"Supports sourcing values from files via \"file://\" and env vars via \"env://\"`.",
					input.FullPopulationInputName,
				),
			})
		}
	}
}

// From https://stackoverflow.com/a/13340826, modified to remove exponents
var jsonNumberRegex = regexp.MustCompile(`^-?(?:0|[1-9]\d*)(?:\.\d+)?$`)

// HandleAttributeFlags takes in a command and a func to call for default (that
// is, set to nil) and non-default values. Suffix can be used to allow this
// logic to be used for various needs, e.g. -attr vs -secret.
func HandleAttributeFlags(c *base.Command, suffix, fullField string, sepFields []base.CombinedSliceFlagValue, defaultFunc func(), setFunc func(map[string]any)) error {
	// If we were given a fullly defined field, use that as-is
	switch fullField {
	case "":
		// Nothing, continue on
	case "null":
		defaultFunc()
		return nil
	default:
		parsedString, err := parseutil.ParsePath(fullField)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			return fmt.Errorf("error parsing %s flag as a URL: %w", suffix, err)
		}
		// We should be able to parse the string as a JSON object
		var setMap map[string]any
		if err := json.Unmarshal([]byte(parsedString), &setMap); err != nil {
			return fmt.Errorf("error parsing %s flag as JSON: %w", suffix, err)
		}
		setFunc(setMap)
		return nil
	}

	setMap := map[string]any{}

	for _, field := range sepFields {
		if len(field.Keys) == 0 {
			// No idea why this would happen, but skip it
			continue
		}

		var val any
		var err error

		// First, perform any needed parsing if we are given the type
		switch field.Name {
		case "num-" + suffix:
			if field.Value == nil {
				return fmt.Errorf("num-%s flag requires a value", suffix)
			}
			switch {
			case strings.Contains(field.Value.GetValue(), "."):
				// JSON treats all numbers equally, however, we will try to be a
				// little better so that we don't include decimals if we don't need
				// to (and don't have to worry about precision if not necessary)
				val, err = strconv.ParseFloat(field.Value.GetValue(), 64)
				if err != nil {
					return fmt.Errorf("error parsing value %q as a float: %w", field.Value, err)
				}
			default:
				val, err = strconv.ParseInt(field.Value.GetValue(), 10, 64)
				if err != nil {
					return fmt.Errorf("error parsing value %q as an integer: %w", field.Value, err)
				}
			}

		case "string-" + suffix:
			if field.Value == nil {
				return fmt.Errorf("string-%s flag requires a value", suffix)
			}
			val = field.Value.GetValue()

		case "bool-" + suffix:
			if field.Value == nil {
				return fmt.Errorf("bool-%s flag requires a value", suffix)
			}
			switch field.Value.GetValue() {
			case "true":
				val = true
			case "false":
				val = false
			default:
				return fmt.Errorf("error parsing value %q as a bool", field.Value)
			}

		case suffix:
			// In this case, use heuristics to just do the right thing the vast
			// majority of the time
			switch {
			case field.Value == nil: // Key-only, set to null

			case field.Value.GetValue() == "null": // Explicit null, we want to set to a null value to clear it
				val = nil

			case field.Value.GetValue() == "true": // bool true
				val = true

			case field.Value.GetValue() == "false": // bool false
				val = false

			case jsonNumberRegex.MatchString(strings.Trim(field.Value.GetValue(), `"`)): // number
				// Same logic as above
				if strings.Contains(field.Value.GetValue(), ".") {
					val, err = strconv.ParseFloat(field.Value.GetValue(), 64)
					if err != nil {
						return fmt.Errorf("error parsing value %q as a float: %w", field.Value, err)
					}
				} else {
					val, err = strconv.ParseInt(field.Value.GetValue(), 10, 64)
					if err != nil {
						return fmt.Errorf("error parsing value %q as an integer: %w", field.Value, err)
					}
				}

			case strings.HasPrefix(field.Value.GetValue(), "["): // serialized JSON array
				var s []any
				u := json.NewDecoder(bytes.NewBufferString(field.Value.GetValue()))
				u.UseNumber()
				if err := u.Decode(&s); err != nil {
					return fmt.Errorf("error parsing value %q as a json array: %w", field.Value, err)
				}
				val = s

			case strings.HasPrefix(field.Value.GetValue(), "{"): // serialized JSON map
				var m map[string]any
				u := json.NewDecoder(bytes.NewBufferString(field.Value.GetValue()))
				u.UseNumber()
				if err := u.Decode(&m); err != nil {
					return fmt.Errorf("error parsing value %q as a json map: %w", field.Value, err)
				}
				val = m

			default:
				// Default is to treat as a string value
				val = field.Value.GetValue()
			}

		default:
			return fmt.Errorf("unknown flag %q", field.Name)
		}

		// Now we have to insert it in the right position in the final map
		currMap := setMap
		for i, segment := range field.Keys {
			if segment == "" {
				return fmt.Errorf("key segment %q for value %q is empty", segment, field.Value)
			}

			switch {
			case i == len(field.Keys)-1:
				// If we get an explicit "null" override whatever is currently
				// there
				if val == nil {
					currMap[segment] = nil
					break
				}
				// We're at the last hop, do the actual insertion
				switch t := currMap[segment].(type) {
				case nil:
					// Nothing currently exists
					currMap[segment] = val

				case []any:
					// It's already a slice, so just append
					currMap[segment] = append(t, val)

				default:
					// It's not a slice, so create a new slice with the
					// existing and new values
					currMap[segment] = []any{t, val}
				}

			default:
				// We need to keep traversing
				switch t := currMap[segment].(type) {
				case nil:
					// We haven't hit this segment before, so create a new
					// object leading off of it and set it to current
					newMap := map[string]any{}
					currMap[segment] = newMap
					currMap = newMap

				case map[string]any:
					// We've seen this before and already have a map so just set
					// that as our new location
					currMap = t

				default:
					// We should only ever be seeing maps if we're not at the
					// final location
					return fmt.Errorf("unexpected type for key segment %q: %T", segment, t)
				}
			}
		}
	}

	if len(setMap) > 0 {
		setFunc(setMap)
	}
	return nil
}
