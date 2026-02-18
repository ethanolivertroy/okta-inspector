package capabilities

// Manifest defines what a restricted binary can do.
type Manifest struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Capabilities Capabilities `yaml:"capabilities"`
	Output      OutputConfig `yaml:"output,omitempty"`
}

type Capabilities struct {
	APIScopes  []string `yaml:"api_scopes"`
	Frameworks []string `yaml:"frameworks"`
	Commands   []string `yaml:"commands"`
	MCPTools   []string `yaml:"mcp_tools,omitempty"`
}

type OutputConfig struct {
	Formats      []string `yaml:"formats,omitempty"`
	AllowArchive bool     `yaml:"allow_archive,omitempty"`
}

// AllFrameworks is the list of all built-in framework IDs.
var AllFrameworks = []string{"stig", "fedramp", "irap", "ismap", "soc2", "pcidss"}

// AllCommands is the list of all CLI commands.
var AllCommands = []string{"audit", "report", "interactive", "serve-mcp", "build", "config", "version"}

// AllScopes is the list of all API scopes.
var AllScopes = []string{
	"policies:read",
	"users:read",
	"apps:read",
	"authenticators:read",
	"logs:read",
	"security:read",
	"identity:read",
}
