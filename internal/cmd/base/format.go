package base

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
)

// This is adapted from the code in the strings package for TrimSpace
var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

func ScopeInfoForOutput(scp *scopes.ScopeInfo, maxLength int) string {
	vals := map[string]interface{}{
		"ID":   scp.Id,
		"Type": scp.Type,
		"Name": scp.Name,
	}
	if scp.ParentScopeId != "" {
		vals["Parent Scope ID"] = scp.ParentScopeId
	}
	return WrapMap(4, maxLength, vals)
}

func MaxAttributesLength(nonAttributesMap, attributesMap map[string]interface{}, keySubstMap map[string]string) int {
	// We always print a scope ID and in some cases this particular key ends up
	// being the longest key, so start with it as a baseline. It's always
	// indented by 2 in addition to the normal offset so take that into account.
	maxLength := len("Parent Scope ID") + 2
	for k := range nonAttributesMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}
	if len(attributesMap) > 0 {
		for k, v := range attributesMap {
			if keySubstMap != nil {
				if keySubstMap[k] != "" {
					attributesMap[keySubstMap[k]] = v
					delete(attributesMap, k)
				}
			}
		}
		for k := range attributesMap {
			if len(k) > maxLength {
				maxLength = len(k)
			}
		}
	}
	return maxLength
}

func trimSpaceRight(in string) string {
	for stop := len(in); stop > 0; stop-- {
		c := in[stop-1]
		if c >= utf8.RuneSelf {
			return strings.TrimFunc(in[:stop], unicode.IsSpace)
		}
		if asciiSpace[c] == 0 {
			return in[0:stop]
		}
	}
	return ""
}

func WrapForHelpText(lines []string) string {
	var ret []string
	for _, line := range lines {
		line = trimSpaceRight(line)
		trimmed := strings.TrimSpace(line)
		diff := uint(len(line) - len(trimmed))
		wrapped := wordwrap.WrapString(trimmed, TermWidth-diff)
		splitWrapped := strings.Split(wrapped, "\n")
		for i := range splitWrapped {
			splitWrapped[i] = fmt.Sprintf("%s%s", strings.Repeat(" ", int(diff)), strings.TrimSpace(splitWrapped[i]))
		}
		ret = append(ret, strings.Join(splitWrapped, "\n"))
	}

	return strings.Join(ret, "\n")
}

func WrapSlice(prefixSpaces int, input []string) string {
	var ret []string
	for _, v := range input {
		ret = append(ret, fmt.Sprintf("%s%s",
			strings.Repeat(" ", prefixSpaces),
			v,
		))
	}

	return strings.Join(ret, "\n")
}

func WrapMap(prefixSpaces, maxLengthOverride int, input map[string]interface{}) string {
	maxKeyLength := maxLengthOverride
	if maxKeyLength == 0 {
		for k := range input {
			if len(k) > maxKeyLength {
				maxKeyLength = len(k)
			}
		}
	}

	var sortedKeys []string
	for k := range input {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	var ret []string
	for _, k := range sortedKeys {
		v := input[k]
		spaces := maxKeyLength - len(k)
		if spaces < 0 {
			spaces = 0
		}
		ret = append(ret, fmt.Sprintf("%s%s%s%s",
			strings.Repeat(" ", prefixSpaces),
			fmt.Sprintf("%s: ", k),
			strings.Repeat(" ", spaces),
			fmt.Sprintf("%v", v),
		))
	}

	return strings.Join(ret, "\n")
}

func PrintApiError(in *api.Error) string {
	nonAttributeMap := map[string]interface{}{
		"Status":  in.ResponseStatus(),
		"Kind":    in.Kind,
		"Message": in.Message,
	}

	if in.Op != "" {
		nonAttributeMap["Operation"] = in.Op
	}

	maxLength := MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Error information:",
		WrapMap(2, maxLength+2, nonAttributeMap),
	}

	if in.Details != nil {
		if len(in.Details.WrappedErrors) > 0 {
			ret = append(ret,
				"",
				"  Wrapped Errors:",
			)
			for _, we := range in.Details.WrappedErrors {
				ret = append(ret,
					fmt.Sprintf("    Message:             %s", we.Message),
					fmt.Sprintf("    Operation:           %s", we.Op),
				)
			}
		}

		if len(in.Details.RequestFields) > 0 {
			ret = append(ret,
				"",
				"  Field-specific Errors:",
			)
			for _, field := range in.Details.RequestFields {
				if field.Name == "update_mask" {
					// TODO: Report useful error messages related to "update_mask".
					continue
				}
				ret = append(ret,
					fmt.Sprintf("    Name:              -%s", strings.ReplaceAll(field.Name, "_", "-")),
					fmt.Sprintf("      Error:           %s", field.Description),
				)
			}
		}
	}

	return WrapForHelpText(ret)
}

// An output formatter for json output of an object
type JsonFormatter struct{}

func (j JsonFormatter) Format(data interface{}) ([]byte, error) {
	return json.Marshal(data)
}

func Format(ui cli.Ui) string {
	switch t := ui.(type) {
	case *BoundaryUI:
		return t.Format
	}

	format := os.Getenv(EnvBoundaryCLIFormat)
	if format == "" {
		format = "table"
	}

	return format
}
