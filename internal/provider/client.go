package provider

import (
	"time"

	nd "github.com/netascode/go-nd"
)

// NDClient is the main provider client that holds shared configuration
// and module-specific clients.
type NDClient struct {
	URL       string
	Username  string
	Password  string
	Domain    string
	Insecure  bool
	Timeout   time.Duration
	ApiClient *nd.Client
	NDModules map[string]interface{}
}

// GetModule returns a module-specific client by name.
// This implements the interface that module packages use to get their clients.
func (c *NDClient) GetModule(name string) interface{} {
	return c.NDModules[name]
}
