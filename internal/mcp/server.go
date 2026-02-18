package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethanolivertroy/okta-inspector/internal/app"
	"github.com/ethanolivertroy/okta-inspector/internal/engine"
	"github.com/ethanolivertroy/okta-inspector/internal/okta"
	"github.com/ethanolivertroy/okta-inspector/internal/version"
)

// Server implements an MCP server for okta-inspector.
type Server struct {
	Domain     string
	AuthHeader string
	app        *app.App
	result     *engine.AuditResult
	snapshot   *okta.Snapshot
}

// NewServer creates a new MCP server.
func NewServer(domain, authHeader string) *Server {
	opts := app.Options{
		Domain:       domain,
		AuthHeader:   authHeader,
		SaveSnapshot: false,
		Format:       "json",
	}
	return &Server{
		Domain:     domain,
		AuthHeader: authHeader,
		app:        app.New(opts),
	}
}

// Tool represents an MCP tool definition.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ListTools returns available MCP tools.
func (s *Server) ListTools() []Tool {
	return []Tool{
		{
			Name:        "run_audit",
			Description: "Run a full compliance audit against the Okta tenant",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"frameworks": map[string]any{
						"type":        "string",
						"description": "Comma-separated framework IDs (stig,fedramp,irap,ismap,soc2,pcidss). Empty for all.",
					},
				},
			},
		},
		{
			Name:        "query_findings",
			Description: "Search and filter audit findings",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"framework": map[string]any{
						"type":        "string",
						"description": "Filter by framework ID",
					},
					"status": map[string]any{
						"type":        "string",
						"description": "Filter by status (pass, fail, manual)",
					},
					"severity": map[string]any{
						"type":        "string",
						"description": "Filter by severity (critical, high, medium, low)",
					},
				},
			},
		},
		{
			Name:        "list_frameworks",
			Description: "List available compliance frameworks",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			Name:        "test_connection",
			Description: "Test connectivity to the Okta API",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			Name:        "get_version",
			Description: "Get okta-inspector version information",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
	}
}

// CallTool handles an MCP tool call.
func (s *Server) CallTool(ctx context.Context, name string, args map[string]any) (string, error) {
	switch name {
	case "run_audit":
		return s.toolRunAudit(ctx, args)
	case "query_findings":
		return s.toolQueryFindings(args)
	case "list_frameworks":
		return s.toolListFrameworks()
	case "test_connection":
		return s.toolTestConnection(ctx)
	case "get_version":
		return version.Full(), nil
	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

func (s *Server) toolRunAudit(ctx context.Context, args map[string]any) (string, error) {
	if fw, ok := args["frameworks"].(string); ok && fw != "" {
		s.app.Options.Frameworks = strings.Split(fw, ",")
	}

	result, err := s.app.RunAudit(ctx)
	if err != nil {
		return "", err
	}
	s.result = result

	data, _ := json.MarshalIndent(map[string]any{
		"domain":         result.Domain,
		"frameworks":     len(result.Frameworks),
		"total_findings": result.TotalFindings,
		"pass":           result.TotalPass,
		"fail":           result.TotalFail,
		"manual":         result.TotalManual,
		"api_calls":      result.APICallCount,
	}, "", "  ")
	return string(data), nil
}

func (s *Server) toolQueryFindings(args map[string]any) (string, error) {
	if s.result == nil {
		return "", fmt.Errorf("no audit results available; run audit first")
	}

	framework, _ := args["framework"].(string)
	status, _ := args["status"].(string)
	severity, _ := args["severity"].(string)

	var filtered []engine.Finding
	for _, fw := range s.result.Frameworks {
		if framework != "" && fw.FrameworkID != framework {
			continue
		}
		for _, f := range fw.Findings {
			if status != "" && string(f.Status) != status {
				continue
			}
			if severity != "" && string(f.Severity) != severity {
				continue
			}
			filtered = append(filtered, f)
		}
	}

	data, _ := json.MarshalIndent(map[string]any{
		"count":    len(filtered),
		"findings": filtered,
	}, "", "  ")
	return string(data), nil
}

func (s *Server) toolListFrameworks() (string, error) {
	frameworks := s.app.Registry.All()
	var list []map[string]any
	for _, fw := range frameworks {
		list = append(list, map[string]any{
			"id":     fw.ID(),
			"name":   fw.Name(),
			"checks": len(fw.Checks()),
		})
	}
	data, _ := json.MarshalIndent(list, "", "  ")
	return string(data), nil
}

func (s *Server) toolTestConnection(ctx context.Context) (string, error) {
	client := okta.NewClient(s.Domain, s.AuthHeader)
	if err := client.TestConnection(ctx); err != nil {
		return fmt.Sprintf(`{"connected": false, "error": "%s"}`, err), nil
	}
	return `{"connected": true}`, nil
}
