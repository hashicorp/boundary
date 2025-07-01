# encrypt package [![Go Reference](https://pkg.go.dev/badge/github.com/hashicorp/eventlogger/filters/encrypt.svg)](https://pkg.go.dev/github.com/hashicorp/eventlogger/filters/encrypt)

The encrypt package implements a new Filter that supports filtering fields in an
event payload using a custom tag named `class`.  This new tag supports two
fields. The first field tag is the classification of the data (valid values are
public, sensitive and secret).  The second field is an optional filter operation
to apply (valid values are redact, encrypt, hmac-sha256).

**tagged struct example**
```go
type testPayloadStruct struct {
    Public    string `class:"public"`
    Sensitive string `class:"sensitive,redact"` // example of classification,operation
    Secret    []byte `class:"secret"`
}

```

encrypt.Filter supports filtering the following struct field types within an
event payload, when they are tagged with a `class` tag:
* `string`
* `[]string`
* `[]byte`
* `[][]byte`
* `wrapperspb.StringValue`
* `wrapperspb.BytesValue`

Note: tagging a map has no affect on it's filtering.  Please see `Taggable
interface` for information about how to filter maps.

The following DataClassifications are supported:
* PublicClassification
* SensitiveClassification
* SecretClassification

The following FilterOperations are supported:
* NoOperation: no filter operation is applied to the field data.
* RedactOperation: redact the field data. 
* EncryptOperation: encrypts the field data.
* HmacSha256Operation: HMAC sha-256 the field data.



# Taggable interface
Go `maps` and `google.protobuf.Struct` in an event payloads can be filtered by
implementing a single function `Taggable` interface, which returns a
`[]PointerTag` for fields that must be filtered.  You may have payloads and/or
payload fields which implement the `Taggable` interface and also contain fields
that are tagged with the `class` tag.

## Important: 
In general, the package defaults assume that unclassified data (including map
fields) are secrets and filters them appropriately.  This means that:
- When a map doesn't implement `Taggable` all of it's fields will be filtered as
  secret data.
- If a map's `Tags(...)` function doesn't return a PointerTag for a field, that
  field will be filtered as secret data.


```go
// Taggable defines an interface for taggable maps
type Taggable interface {
	// Tags will return a set of pointer tags for the map
	Tags() ([]PointerTag, error)
}

// PointerTag provides the pointerstructure pointer string to get/set a key
// within a map or struct.Value along with its DataClassification and
// FilterOperation.
type PointerTag struct {
	// Pointer is the pointerstructure pointer string to get/set a key within a
	// map[string]interface{}  See: https://github.com/mitchellh/pointerstructure
	Pointer string

	// Classification is the DataClassification of data pointed to by the
	// Pointer
	Classification DataClassification

	// Filter is the FilterOperation to apply to the data pointed to by the
	// Pointer.  This is optional and the default operations (or overrides) will
	// apply when not specified
	Filter FilterOperation
}
``` 

# Filter operation overrides

The Filter node will contain an optional field:

`FilterOperationOverrides map[DataClassification]FilterOperation`

This map can provide an optional set of runtime overrides for the FilterOperations to be applied to DataClassifications.

Normally, the filter operation applied to a field is determined by the operation
specified in its class tag. If no operation is specified in the tag, then a
set of reasonable default filter operations are applied. 

FilterOperationOverrides provides the ability to override an event's "class" tag settings.


# Default filter operations
* PublicClassification: NoOperation
* SensitiveClassification: EncryptOperation
* SecretClassification: RedactOperation
* NoClassification: RedactOperation

Note: The function `encrypt.DefaultFilterOperations()` returns a `map[DataClassification]FilterOperation` of
these defaults. 