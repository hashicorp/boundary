package api

import (
	"bytes"

	"github.com/fatih/structs"
)

func init() {
	structs.DefaultTagName = "json"
}

type GenericResult interface {
	GetItem() interface{}
	GetResponseBody() *bytes.Buffer
	GetResponseMap() map[string]interface{}
}

type GenericDeleteResult interface {
	GetResponseBody() *bytes.Buffer
	GetResponseMap() map[string]interface{}
}

type GenericListResult interface {
	GetItems() interface{}
	GetResponseBody() *bytes.Buffer
	GetResponseMap() map[string]interface{}
}
