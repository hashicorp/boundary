package groups

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/kr/pretty"
	"github.com/mitchellh/pointerstructure"
	"github.com/stretchr/testify/require"
)

var inputJson = `
{
	"num": 5,
	"id": "from-sub",
	"issuer": "from-iss",
	"email": "from-email",
	"audiences": ["from-aud"],
	"claims": {
		"app_metadata": {
			"authorization": {
				"roles": ["admin","editor"]
			}
		}
	}
}
`

func TestDynamicGroups_Basic(t *testing.T) {
	require := require.New(t)
	var m map[string]interface{}
	decoder := json.NewDecoder(bytes.NewBufferString(inputJson))
	decoder.UseNumber()
	require.NoError(decoder.Decode(&m))
	val, err := pointerstructure.Get(m, "/claims/app_metadata/authorization/roles/0")
	require.NoError(err)
	pretty.Println(val)
}
