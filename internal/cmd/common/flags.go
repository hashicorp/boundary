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
				Name:   "id",
				Target: &c.FlagId,
				Usage:  fmt.Sprintf("ID of the %s on which to operate.", resourceType),
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
			f.IntVar(&base.IntVar{
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

func PopulateAttributeFlags(c *base.Command, f *base.FlagSet, flagNames map[string][]string, command string) {
	keyDelimiter := "."
	for _, name := range flagNames[command] {
		switch name {
		case "attributes":
			f.StringVar(&base.StringVar{
				Name:   "attributes",
				Target: &c.FlagAttributes,
				Usage:  `A JSON map value to use as the entirety of the request's attributes map. Usually this will be sourced from a file via "file://" syntax. Is exclusive with the other attr flags.`,
			})
		case "attr":
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "attr",
				Target:         &c.FlagAttrs,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage:          `A key=value attribute to add to the request's attributes map. The type is automatically inferred. Use -string-attr, -bool-attr, or -num-attr if the type needs to be overridden. Can be specified multiple times. Supports sourcing values from files via "file://" and env vars via "env://"`,
			})
		case "string-attr":
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "string-attr",
				Target:         &c.FlagAttrs,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage:          `A key=value string attribute to add to the request's attributes map. Can be specified multiple times. Supports sourcing values from files via "file://" and env vars via "env://"`,
			})
		case "bool-attr":
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "bool-attr",
				Target:         &c.FlagAttrs,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage:          `A key=value bool attribute to add to the request's attributes map. Can be specified multiple times. Supports sourcing values from files via "file://" and env vars via "env://"`,
			})
		case "num-attr":
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "num-attr",
				Target:         &c.FlagAttrs,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage:          `A key=value numeric attribute to add to the request's attributes map. Can be specified multiple times. Supports sourcing values from files via "file://" and env vars via "env://"`,
			})
		}
	}
}

func PopulateSecretFlags(c *base.Command, f *base.FlagSet, flagNames map[string][]string, command string) {
	keyDelimiter := "."
	for _, name := range flagNames[command] {
		switch name {
		case "secrets":
			f.StringVar(&base.StringVar{
				Name:   "secrets",
				Target: &c.FlagSecrets,
				Usage:  `A JSON map value to use as the entirety of the request's secrets map. Usually this will be sourced from a file via "file://" syntax. Is exclusive with the other secret flags.`,
			})
		case "secret":
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "secret",
				Target:         &c.FlagScrts,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage:          `A key=value secret to add to the request's secrets map. The type is automatically inferred. Use -string-secret, -bool-secret, or -num-secret if the type needs to be overridden. Can be specified multiple times. Supports sourcing values from files via "file://" and env vars via "env://"`,
			})
		case "string-secret":
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "string-secret",
				Target:         &c.FlagScrts,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage:          `A key=value string secret to add to the request's secrets map. Can be specified multiple times. Supports sourcing values from files via "file://" and env vars via "env://"`,
			})
		case "bool-secret":
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "bool-secret",
				Target:         &c.FlagScrts,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage:          `A key=value bool secret to add to the request's secrets map. Can be specified multiple times. Supports sourcing values from files via "file://" and env vars via "env://"`,
			})
		case "num-secret":
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "num-secret",
				Target:         &c.FlagScrts,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage:          `A key=value numeric secret to add to the request's secrets map. Can be specified multiple times. Supports sourcing values from files via "file://" and env vars via "env://"`,
			})
		}
	}
}

func PopulateObjectFlags(c *base.Command, f *base.FlagSet, flagNames map[string][]string, command string) {
	keyDelimiter := "."
	for _, name := range flagNames[command] {
		switch name {
		case "object":
			f.StringVar(&base.StringVar{
				Name:   "object",
				Target: &c.FlagObject,
				Usage:  `A JSON map value to use as the entirety of the request's object map. Usually this will be sourced from a file via "file://" syntax. Is exclusive with the other kv flags.`,
			})
		case "kv":
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "kv",
				Target:         &c.FlagKv,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage:          `A key=value pair to add to the request's object map. The type is automatically inferred. Use -string-kv, -bool-kv, or -num-kv if the type needs to be overridden. Can be specified multiple times. Supports sourcing values from files via "file://" and env vars via "env://"`,
			})
		case "string-kv":
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "string-kv",
				Target:         &c.FlagKv,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage:          `A key=value string value to add to the request's object map. Can be specified multiple times. Supports sourcing values from files via "file://" and env vars via "env://"`,
			})
		case "bool-kv":
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "bool-kv",
				Target:         &c.FlagKv,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage:          `A key=value bool value to add to the request's object map. Can be specified multiple times. Supports sourcing values from files via "file://" and env vars via "env://"`,
			})
		case "num-kv":
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:           "num-kv",
				Target:         &c.FlagKv,
				KvSplit:        true,
				KeyDelimiter:   &keyDelimiter,
				ProtoCompatKey: true,
				Usage:          `A key=value numeric value to add to the request's object map. Can be specified multiple times. Supports sourcing values from files via "file://" and env vars via "env://"`,
			})
		}
	}
}

// From https://stackoverflow.com/a/13340826, modified to remove exponents
var jsonNumberRegex = regexp.MustCompile(`^-?(?:0|[1-9]\d*)(?:\.\d+)?$`)

// HandleAttributeFlags takes in a command and a func to call for default (that
// is, set to nil) and non-default values. Suffix can be used to allow this
// logic to be used for various needs, e.g. -attr vs -secret.
func HandleAttributeFlags(c *base.Command, suffix, fullField string, sepFields []base.CombinedSliceFlagValue, defaultFunc func(), setFunc func(map[string]interface{})) error {
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
		var setMap map[string]interface{}
		if err := json.Unmarshal([]byte(parsedString), &setMap); err != nil {
			return fmt.Errorf("error parsing %s flag as JSON: %w", suffix, err)
		}
		setFunc(setMap)
		return nil
	}

	setMap := map[string]interface{}{}

	for _, field := range sepFields {
		if len(field.Keys) == 0 {
			// No idea why this would happen, but skip it
			continue
		}

		var val interface{}
		var err error

		// First, perform any needed parsing if we are given the type
		switch field.Name {
		case "num-" + suffix:
			// JSON treats all numbers equally, however, we will try to be a
			// little better so that we don't include decimals if we don't need
			// to (and don't have to worry about precision if not necessary)
			if strings.Contains(field.Value, ".") {
				val, err = strconv.ParseFloat(field.Value, 64)
				if err != nil {
					return fmt.Errorf("error parsing value %q as a float: %w", field.Value, err)
				}
			} else {
				val, err = strconv.ParseInt(field.Value, 10, 64)
				if err != nil {
					return fmt.Errorf("error parsing value %q as an integer: %w", field.Value, err)
				}
			}

		case "string-" + suffix:
			val = strings.Trim(field.Value, `"`)

		case "bool-" + suffix:
			switch field.Value {
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
			case field.Value == "null": // Explicit null, we want to set to a null value to clear it
				val = nil

			case field.Value == "true": // bool true
				val = true

			case field.Value == "false": // bool false
				val = false

			case strings.HasPrefix(field.Value, `"`): // explicitly quoted string
				val = strings.Trim(field.Value, `"`)

			case jsonNumberRegex.MatchString(strings.Trim(field.Value, `"`)): // number
				// Same logic as above
				if strings.Contains(field.Value, ".") {
					val, err = strconv.ParseFloat(field.Value, 64)
					if err != nil {
						return fmt.Errorf("error parsing value %q as a float: %w", field.Value, err)
					}
				} else {
					val, err = strconv.ParseInt(field.Value, 10, 64)
					if err != nil {
						return fmt.Errorf("error parsing value %q as an integer: %w", field.Value, err)
					}
				}

			case strings.HasPrefix(field.Value, "["): // serialized JSON array
				var s []interface{}
				u := json.NewDecoder(bytes.NewBufferString(field.Value))
				u.UseNumber()
				if err := u.Decode(&s); err != nil {
					return fmt.Errorf("error parsing value %q as a json array: %w", field.Value, err)
				}
				val = s

			case strings.HasPrefix(field.Value, "{"): // serialized JSON map
				var m map[string]interface{}
				u := json.NewDecoder(bytes.NewBufferString(field.Value))
				u.UseNumber()
				if err := u.Decode(&m); err != nil {
					return fmt.Errorf("error parsing value %q as a json map: %w", field.Value, err)
				}
				val = m

			default:
				// Default is to treat as a string value
				val = field.Value
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

				case []interface{}:
					// It's already a slice, so just append
					currMap[segment] = append(t, val)

				default:
					// It's not a slice, so create a new slice with the
					// exisitng and new values
					currMap[segment] = []interface{}{t, val}
				}

			default:
				// We need to keep traversing
				switch t := currMap[segment].(type) {
				case nil:
					// We haven't hit this segment before, so create a new
					// object leading off of it and set it to current
					newMap := map[string]interface{}{}
					currMap[segment] = newMap
					currMap = newMap

				case map[string]interface{}:
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
