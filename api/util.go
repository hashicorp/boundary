package api

type GenericResult interface {
	GetItem() interface{}
	GetResponse() *Response
}

type GenericDeleteResult interface {
	GetResponse() *Response
}

type GenericListResult interface {
	GetItems() interface{}
	GetResponse() *Response
}
