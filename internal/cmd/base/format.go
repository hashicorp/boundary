package base

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
)

// This is adapted from the code in the strings package for TrimSpace
var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

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
			fmt.Sprintf("%s: ", v),
		))
	}

	return strings.Join(ret, "\n")
}

func WrapMap(prefixSpaces, maxLengthOverride int, input map[string]interface{}) string {
	maxKeyLength := maxLengthOverride
	var sortedKeys []string
	if maxKeyLength == 0 {
		for k := range input {
			sortedKeys = append(sortedKeys, k)
			if len(k) > maxKeyLength {
				maxKeyLength = len(k)
			}
		}
	}
	sort.Strings(sortedKeys)
	var ret []string
	for _, k := range sortedKeys {
		v := input[k]
		spaces := maxKeyLength - len(k)
		ret = append(ret, fmt.Sprintf("%s%s%s%s",
			strings.Repeat(" ", prefixSpaces),
			fmt.Sprintf("%s: ", k),
			strings.Repeat(" ", spaces),
			fmt.Sprintf("%v", v),
		))
	}

	return strings.Join(ret, "\n")
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
