package targets

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// DecodeJsonSecret converts base64 encoded json strings into a go map.
// Numerical values in the map are of type json.Number.
func DecodeJsonSecret(in string) (map[string]interface{}, error) {
	ret := make(map[string]interface{})
	dec := json.NewDecoder(base64.NewDecoder(base64.StdEncoding, strings.NewReader(in)))
	dec.UseNumber()
	if err := dec.Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
}
