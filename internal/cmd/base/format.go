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
	"github.com/hashicorp/boundary/api/plugins"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/version"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/pkg/errors"
)

// This is adapted from the code in the strings package for TrimSpace
var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

func ScopeInfoForOutput(scp *scopes.ScopeInfo, maxLength int) string {
	if scp == nil {
		return "    <not included in response>"
	}
	vals := map[string]any{
		"ID":   scp.Id,
		"Type": scp.Type,
		"Name": scp.Name,
	}
	if scp.ParentScopeId != "" {
		vals["Parent Scope ID"] = scp.ParentScopeId
	}
	return WrapMap(4, maxLength, vals)
}

func PluginInfoForOutput(plg *plugins.PluginInfo, maxLength int) string {
	if plg == nil {
		return "    <not included in response>"
	}
	vals := map[string]any{
		"ID":   plg.Id,
		"Name": plg.Name,
	}
	return WrapMap(4, maxLength, vals)
}

func MaxAttributesLength(nonAttributesMap, attributesMap map[string]any, keySubstMap map[string]string) int {
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

func WrapMap(prefixSpaces, maxLengthOverride int, input map[string]any) string {
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

		if sv, ok := v.([]string); ok {
			nv := make([]string, 0, len(sv))
			for _, si := range sv {
				nv = append(nv, fmt.Sprintf("%q", si))
			}
			v = nv
		}

		vOut := fmt.Sprintf("%v", v)
		switch v.(type) {
		case map[string]any:
			buf, err := json.MarshalIndent(v, strings.Repeat(" ", prefixSpaces), "  ")
			if err != nil {
				vOut = "[Unable to Print]"
				break
			}
			bStrings := strings.Split(string(buf), "\n")
			if len(bStrings) > 0 {
				// Indent doesn't apply to the first line 🙄
				bStrings[0] = fmt.Sprintf("\n%s%s", strings.Repeat(" ", prefixSpaces), bStrings[0])
			}
			vOut = strings.Join(bStrings, "\n")
		}
		ret = append(ret, fmt.Sprintf("%s%s%s%s",
			strings.Repeat(" ", prefixSpaces),
			fmt.Sprintf("%s: ", k),
			strings.Repeat(" ", spaces),
			vOut,
		))
	}

	return strings.Join(ret, "\n")
}

// PrintApiError prints the given API error, optionally with context
// information, to the UI in the appropriate format.  WithAttributeFieldPrefix is
// used, all other options are ignored.
func (c *Command) PrintApiError(in *api.Error, contextStr string, opt ...Option) {
	opts := getOpts(opt...)
	switch Format(c.UI) {
	case "json":
		var b []byte
		if version.SupportsFeature(version.Binary, version.IncludeStatusInCli) {
			output := struct {
				Context    string          `json:"context,omitempty"`
				StatusCode int             `json:"status_code"`
				Status     int             `json:"status"`
				ApiError   json.RawMessage `json:"api_error"`
			}{
				Context:    contextStr,
				StatusCode: in.Response().StatusCode(),
				Status:     in.Response().StatusCode(),
				ApiError:   in.Response().Body.Bytes(),
			}
			b, _ = JsonFormatter{}.Format(output)
		} else {
			output := struct {
				Context    string          `json:"context,omitempty"`
				StatusCode int             `json:"status_code"`
				ApiError   json.RawMessage `json:"api_error"`
			}{
				Context:    contextStr,
				StatusCode: in.Response().StatusCode(),
				ApiError:   in.Response().Body.Bytes(),
			}
			b, _ = JsonFormatter{}.Format(output)
		}
		c.UI.Error(string(b))

	default:
		nonAttributeMap := map[string]any{
			"Status":  in.Response().StatusCode(),
			"Kind":    in.Kind,
			"Message": in.Message,
		}
		if contextStr != "" {
			nonAttributeMap["context"] = contextStr
		}
		if in.Op != "" {
			nonAttributeMap["Operation"] = in.Op
		}

		maxLength := MaxAttributesLength(nonAttributeMap, nil, nil)

		var output []string
		if contextStr != "" {
			output = append(output, contextStr)
		}
		output = append(output,
			"",
			"Error information:",
			WrapMap(2, maxLength+2, nonAttributeMap),
		)

		if in.Details != nil {
			if len(in.Details.WrappedErrors) > 0 {
				output = append(output,
					"",
					"  Wrapped Errors:",
				)
				for _, we := range in.Details.WrappedErrors {
					output = append(output,
						fmt.Sprintf("    Message:             %s", we.Message),
						fmt.Sprintf("    Operation:           %s", we.Op),
					)
				}
			}

			if len(in.Details.RequestFields) > 0 {
				output = append(output,
					"",
					"  Field-specific Errors:",
				)
				for _, field := range in.Details.RequestFields {
					if field.Name == "update_mask" {
						// TODO: Report useful error messages related to "update_mask".
						continue
					}
					var fNameParts []string
					if opts.withAttributeFieldPrefix != "" && strings.HasPrefix(field.Name, "attributes.") {
						fNameParts = append(fNameParts, opts.withAttributeFieldPrefix)
					}
					fNameParts = append(fNameParts, strings.ReplaceAll(strings.TrimPrefix(field.Name, "attributes."), "_", "-"))
					fName := strings.Join(fNameParts, "-")
					output = append(output,
						fmt.Sprintf("    Name:              -%s", fName),
						fmt.Sprintf("      Error:           %s", field.Description),
					)
				}
			}
		}

		c.UI.Error(WrapForHelpText(output))
	}
}

// PrintCliError prints the given CLI error to the UI in the appropriate format
func (c *Command) PrintCliError(err error) {
	switch Format(c.UI) {
	case "table":
		c.UI.Error(err.Error())
	case "json":
		output := struct {
			Error string `json:"error"`
		}{
			Error: err.Error(),
		}
		b, _ := JsonFormatter{}.Format(output)
		c.UI.Error(string(b))
	}
}

// PrintJsonItem prints the given item to the UI in JSON format
func (c *Command) PrintJsonItem(resp *api.Response, opt ...Option) bool {
	if resp == nil {
		c.PrintCliError(errors.New("Error formatting as JSON: no response given to item formatter"))
		return false
	}
	if r := resp.HttpResponse(); r != nil {
		opt = append(opt, WithStatusCode(r.StatusCode))
	}
	return c.PrintJson(resp.Body.Bytes(), opt...)
}

// PrintJson prints the given raw JSON in our common format
func (c *Command) PrintJson(input json.RawMessage, opt ...Option) bool {
	opts := getOpts(opt...)
	output := struct {
		StatusCode int             `json:"status_code,omitempty"`
		Item       json.RawMessage `json:"item,omitempty"`
	}{
		StatusCode: opts.withStatusCode,
		Item:       input,
	}
	b, err := JsonFormatter{}.Format(output)
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error formatting as JSON: %w", err))
		return false
	}
	c.UI.Output(string(b))
	return true
}

// PrintJsonItems prints the given items to the UI in JSON format
func (c *Command) PrintJsonItems(resp *api.Response) bool {
	if resp == nil {
		c.PrintCliError(errors.New("Error formatting as JSON: no response given to items formatter"))
		return false
	}
	// First we need to grab the items out. The reason is that if we simply
	// embed the raw message as with PrintJsonItem above, it will have {"items":
	// {"items": []}}. However, we decode into a RawMessage which makes it much
	// more efficient on both the decoding and encoding side.
	type inMsg struct {
		Items json.RawMessage `json:"items"`
	}
	var input inMsg
	if resp.Body.Bytes() != nil {
		if err := json.Unmarshal(resp.Body.Bytes(), &input); err != nil {
			c.PrintCliError(fmt.Errorf("Error unmarshaling response body at format time: %w", err))
			return false
		}
	}
	output := struct {
		StatusCode int             `json:"status_code"`
		Items      json.RawMessage `json:"items"`
	}{
		StatusCode: resp.HttpResponse().StatusCode,
		Items:      input.Items,
	}
	b, err := JsonFormatter{}.Format(output)
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error formatting as JSON: %w", err))
		return false
	}
	c.UI.Output(string(b))
	return true
}

// An output formatter for json output of an object
type JsonFormatter struct{}

func (j JsonFormatter) Format(data any) ([]byte, error) {
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
