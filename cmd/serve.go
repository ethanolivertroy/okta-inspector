package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ethanolivertroy/okta-inspector/internal/config"
	"github.com/ethanolivertroy/okta-inspector/internal/mcp"
	"github.com/spf13/cobra"
)

var (
	serveTransport string
)

var serveCmd = &cobra.Command{
	Use:   "serve-mcp",
	Short: "Start MCP server for AI assistant integration",
	Long: `Start an MCP (Model Context Protocol) server that exposes
okta-inspector tools for AI assistant integration.

Supports stdio transport (default) for use with Claude Code, Cursor, etc.`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVar(&serveTransport, "transport", "stdio", "transport type: stdio")
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	domain, _ := config.ResolveDomain(flagDomain)
	var authHeader string
	if auth, err := config.ResolveAuth(flagToken, flagOAuth); err == nil {
		authHeader = auth.AuthHeader()
	}

	server := mcp.NewServer(domain, authHeader)

	switch serveTransport {
	case "stdio":
		return runStdioServer(server)
	default:
		return fmt.Errorf("unsupported transport: %s", serveTransport)
	}
}

// runStdioServer implements a simple JSON-RPC over stdio MCP server.
func runStdioServer(server *mcp.Server) error {
	reader := bufio.NewReader(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		var req struct {
			JSONRPC string         `json:"jsonrpc"`
			ID      any            `json:"id"`
			Method  string         `json:"method"`
			Params  map[string]any `json:"params,omitempty"`
		}

		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}

		var result any
		var rpcErr *rpcError

		switch req.Method {
		case "initialize":
			result = map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    "okta-inspector",
					"version": "1.0.0",
				},
			}
		case "tools/list":
			result = map[string]any{
				"tools": server.ListTools(),
			}
		case "tools/call":
			toolName, ok := req.Params["name"].(string)
			if !ok || toolName == "" {
				rpcErr = &rpcError{Code: -32602, Message: "missing or invalid 'name' parameter"}
				break
			}
			toolArgs, _ := req.Params["arguments"].(map[string]any)
			if toolArgs == nil {
				toolArgs = make(map[string]any)
			}
			content, err := server.CallTool(context.Background(), toolName, toolArgs)
			if err != nil {
				rpcErr = &rpcError{Code: -32000, Message: err.Error()}
			} else {
				result = map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": content},
					},
				}
			}
		default:
			rpcErr = &rpcError{Code: -32601, Message: "method not found"}
		}

		resp := map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
		}
		if rpcErr != nil {
			resp["error"] = rpcErr
		} else {
			resp["result"] = result
		}

		if err := encoder.Encode(resp); err != nil {
			return err
		}
	}
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
