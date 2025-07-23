// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package mcpserver

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Example schema for the warehouse tables:
//
// Table "public.wh_credential_group"
// Column |    Type    | Collation | Nullable |   Default
// --------+------------+-----------+----------+--------------
// key    | wh_dim_key |           | not null | wh_dim_key()
// Indexes:
//
//	"wh_credential_group_pkey" PRIMARY KEY, btree (key)
//
// Referenced by:
//
//	TABLE "wh_session_accumulating_fact" CONSTRAINT "wh_credential_group_credential_group_key_fkey" FOREIGN KEY (credential_group_key) REFERENCES wh_credential_group(key) ON UPDATE CASCADE ON DELETE RESTRICT
//	TABLE "wh_session_connection_accumulating_fact" CONSTRAINT "wh_credential_group_credential_group_key_fkey" FOREIGN KEY (credential_group_key) REFERENCES wh_credential_group(key) ON UPDATE CASCADE ON DELETE RESTRICT
//	TABLE "wh_credential_group_membership" CONSTRAINT "wh_credential_group_membership_credential_group_key_fkey" FOREIGN KEY (credential_group_key) REFERENCES wh_credential_group(key) ON UPDATE CASCADE ON DELETE RESTRICT
//
//go:embed schema.txt
var schemaFile string

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

	mcp.AddTool(s, &mcp.Tool{Name: "get_warehouse_schemas", Description: "Get a string blob all warehouse schemas in the database"}, srv.GetWarehouseSchemas)
	mcp.AddTool(s, &mcp.Tool{Name: "run_sql_query", Description: "Run an arbitrary SQL query against the warehouse"}, srv.RunSQLQuery)

	return srv
}

type GetWarehouseSchemasParams struct{}

type GetWarehouseSchemasResult struct {
	Schemas []string `json:"schemas" jsonschema:"list of schemas"`
}

// GetWarehouseSchemas reads a premade database dump of the warehouse tables from a file and returns it as a string blob.
func (s *MCPServer) GetWarehouseSchemas(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[GetWarehouseSchemasParams]) (*mcp.CallToolResultFor[GetWarehouseSchemasResult], error) {
	resp := GetWarehouseSchemasResult{
		Schemas: []string{schemaFile},
	}

	jsonContent, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scopes to JSON: %w", err)
	}

	// Return the result with the schemas
	return &mcp.CallToolResultFor[GetWarehouseSchemasResult]{
		Content: []mcp.Content{&mcp.TextContent{
			Text: string(jsonContent),
		}},
		StructuredContent: resp,
	}, nil
}

type RunSQLQueryParams struct {
	Query string `json:"query" jsonschema:"the SQL query string to run"`
}

type RunSQLQueryResult struct {
	Results []any `json:"results" jsonschema:"the query results"`
}

func (s *MCPServer) RunSQLQuery(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[RunSQLQueryParams]) (*mcp.CallToolResultFor[RunSQLQueryResult], error) {
	warehouseRepo, err := s.warehouseRepoFn()
	if err != nil {
		return nil, fmt.Errorf("failed to get warehouse repository: %w", err)
	}
	if warehouseRepo == nil {
		return nil, fmt.Errorf("warehouse repository is nil")
	}

	results, err := warehouseRepo.RunSQLQuery(ctx, params.Arguments.Query)
	if err != nil {
		return nil, fmt.Errorf("failed to run SQL query: %w", err)
	}

	resp := RunSQLQueryResult{
		Results: results,
	}

	// Convert the result to JSON if needed
	jsonContent, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query results to JSON: %w", err)
	}

	// Return the result with the query results
	return &mcp.CallToolResultFor[RunSQLQueryResult]{
		Content: []mcp.Content{&mcp.TextContent{
			Text: string(jsonContent),
		}},
		StructuredContent: resp,
	}, nil
}
