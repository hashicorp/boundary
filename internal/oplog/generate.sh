#!/bin/bash


set -e 
# use gogo protobuf gen to remove XXX_* fields from generated pb source
#   go get github.com/gogo/protobuf/protoc-gen-gofast 

protoc -I=./store -I=$GOPATH/src -I=$GOPATH/src/github.com/gogo/protobuf/protobuf  --go-json_out=./store --gogofaster_out=paths=source_relative,\
Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/duration.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/struct.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/wrappers.proto=github.com/gogo/protobuf/types:. \
    store/oplog.proto
mv oplog.pb.go store/

# now, inject custom gorm tags using: 
#   go get github.com/favadi/protoc-go-inject-tag 
protoc-go-inject-tag -input=store/oplog.pb.go


protoc -I=./any -I=$GOPATH/src -I=$GOPATH/src/github.com/gogo/protobuf/protobuf  --gogofaster_out=paths=source_relative,\
Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/duration.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/struct.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/wrappers.proto=github.com/gogo/protobuf/types:. \
    any/any.proto
mv any.pb.go any/


protoc -I=./oplog_test -I=$GOPATH/src -I=$GOPATH/src/github.com/gogo/protobuf/protobuf  --gogofaster_out=paths=source_relative,\
Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/duration.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/struct.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/wrappers.proto=github.com/gogo/protobuf/types:. \
    oplog_test/oplog_test.proto
mv oplog_test.pb.go oplog_test/

