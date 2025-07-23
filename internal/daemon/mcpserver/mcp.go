// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GetMCPServerHandler returns an HTTP handler that serves the MCP server.
//
// It uses the provided warehouseRepoFn to access the warehouse repository.
func GetMCPServerHandler(ctx context.Context, warehouseRepoFn common.WarehouseRepoFactory) (http.Handler, error) {
	const op = "mcpserver.GetMCPServerHandler"
	if warehouseRepoFn == nil {
		return nil, fmt.Errorf("%s: received nil warehouse repo function", op)
	}

	server := NewServer(warehouseRepoFn)

	h := mcp.NewStreamableHTTPHandler(func(request *http.Request) *mcp.Server {
		return server.server
	}, nil)
	return h, nil
}

type MCPServer struct {
	server *mcp.Server

	warehouseRepoFn common.WarehouseRepoFactory
}

func NewServer(warehouseRepoFn common.WarehouseRepoFactory) *MCPServer {
	s := mcp.NewServer(&mcp.Implementation{Name: "boundary", Version: "v0.0.1"}, nil)

	srv := &MCPServer{
		server:          s,
		warehouseRepoFn: warehouseRepoFn,
	}

	// TODO: We plan on reading from a file on disk instead of the database.
	mcp.AddTool(s, &mcp.Tool{Name: "get_warehouse_schemas", Description: "Get a string blob all warehouse schemas in the database"}, srv.GetWarehouseSchemas)

	// TODO: Add an mcp.AddTool to run arbitrary SQL queries

	return srv
}

type GetWarehouseSchemasParams struct{}

type GetWarehouseSchemasResult struct {
	Schemas []string `json:"schemas" jsonschema:"list of schemas"`
}

func (s *MCPServer) GetWarehouseSchemas(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[GetWarehouseSchemasParams]) (*mcp.CallToolResultFor[GetWarehouseSchemasResult], error) {
	warehouseRepo, err := s.warehouseRepoFn()
	if err != nil {
		return nil, fmt.Errorf("failed to get warehouse repository: %w", err)
	}
	if warehouseRepo == nil {
		return nil, fmt.Errorf("warehouse repository is nil")
	}

	resultItems, err := warehouseRepo.GetWarehouseSchemas(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get warehouse schemas: %w", err)
	}

	resp := GetWarehouseSchemasResult{
		Schemas: resultItems,
	}

	// Convert the result to JSON if needed
	jsonContent, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scopes to JSON: %w", err)
	}

	// Return the result with the schemas
	return &mcp.CallToolResultFor[GetWarehouseSchemasResult]{
		Content: []mcp.Content{&mcp.TextContent{
			Text: string(jsonContent),
		}}, // must be empty but set if using StructuredContent
		StructuredContent: resp,
	}, nil
}
