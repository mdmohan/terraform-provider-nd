# Adding a New Module to Terraform Provider ND

This guide explains how to add a new submodule (like `onemanage`, `insights`, etc.) to the Terraform Provider using the registry pattern with shared API client.

## Architecture Overview

The provider uses a **registry pattern with shared API client**:

1. **Registry Pattern**: Resources self-register via `init()` functions
2. **Shared API Client**: All modules share the same `*nd.Client` instance
3. **Eager Initialization**: Modules are created during provider configuration
4. **No Cyclic Imports**: Clean separation of concerns via the `registry` package

### Component Structure

```
internal/
├── registry/           # Shared interfaces (no domain imports)
│   └── registry.go     # ClientProvider interface, registration functions
├── provider/           # Provider configuration
│   ├── provider.go     # Main provider logic
│   └── client.go       # NDClient with shared API client
├── manage/             # Example module
│   ├── manage.go       # Module client
│   ├── register.go     # Returns registered resources
│   └── resource_*/     # Individual resources
│       ├── init.go     # Auto-registration
│       └── *.go        # Resource implementation
└── onemanage/          # Your new module (to be created)
```

## Step-by-Step Guide

### Step 1: Create Module Package Structure

Create the following directory structure:

```
internal/onemanage/
├── manage.go           # Module client and initialization
├── register.go         # Resource/datasource retrieval
└── resource_*/         # Your resources
    ├── init.go
    └── *.go
```

### Step 2: Implement Module Client (`onemanage/manage.go`)

```go
package onemanage

import (
	nd "github.com/netascode/go-nd"
)

const ModuleKey = "onemanage"

type OneManageClient struct {
	ApiClient *nd.Client
}

var onemanageInstance *OneManageClient

// NewClient creates the onemanage module with the shared API client
func NewClient(client *nd.Client) *OneManageClient {
	if onemanageInstance == nil {
		onemanageInstance = &OneManageClient{
			ApiClient: client,
		}
	}
	return onemanageInstance
}
```

**Key Points:**
- Module key should be unique across all modules
- Client receives the shared `*nd.Client` instance
- Singleton pattern prevents multiple instances
- No error handling needed (client already created by provider)

### Step 3: Create Registry Integration (`onemanage/register.go`)

```go
package onemanage

import (
	"terraform-provider-nd/internal/registry"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// GetResources returns all resources for the onemanage module.
// Resources auto-register via init() in their packages.
func GetResources() []func() resource.Resource {
	return registry.GetResources(ModuleKey)
}

// GetDataSources returns all data sources for the onemanage module.
// Data sources auto-register via init() in their packages.
func GetDataSources() []func() datasource.DataSource {
	return registry.GetDataSources(ModuleKey)
}
```

### Step 4: Create a Resource with Auto-Registration

Example: `onemanage/resource_example/init.go`

```go
package resource_example

import (
	"terraform-provider-nd/internal/registry"
)

const ModuleKey = "onemanage"

func init() {
	registry.RegisterResource(ModuleKey, NewExampleResource)
}
```

Example: `onemanage/resource_example/example.go`

```go
package resource_example

import (
	"context"
	"fmt"

	"terraform-provider-nd/internal/onemanage"
	"terraform-provider-nd/internal/registry"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var (
	_ resource.Resource              = &exampleResource{}
	_ resource.ResourceWithConfigure = &exampleResource{}
)

type exampleResource struct {
	client *onemanage.OneManageClient
}

func NewExampleResource() resource.Resource {
	return &exampleResource{}
}

func (r *exampleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(registry.ClientProvider)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected registry.ClientProvider, got: %T.", req.ProviderData),
		)
		return
	}

	module := client.GetModule(ModuleKey)
	if module == nil {
		resp.Diagnostics.AddError(
			"OneManage Module Not Found",
			"The onemanage module was not registered with the provider.",
		)
		return
	}

	r.client = module.(*onemanage.OneManageClient)
}

// Implement Metadata, Schema, Create, Read, Update, Delete methods...
```

### Step 5: Register Module in Provider (`provider/provider.go`)

Add your module to the module registration in `Configure()`:

```go
// Register module-specific clients (eager initialization)
// Each team adds one line here for their module
ndClient.NDModules[manage.ModuleKey] = manage.NewManage(&client)
ndClient.NDModules[onemanage.ModuleKey] = onemanage.NewClient(&client)
```

### Step 6: Register Resources/DataSources in Provider

In `provider.go`, add your module's resources and data sources:

```go
// DataSources
func (p *NexusDashboardProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	dataSources := []func() datasource.DataSource{}
	dataSources = append(dataSources, manage.GetDataSources()...)
	dataSources = append(dataSources, onemanage.GetDataSources()...)  // Add this line
	return dataSources
}

// Resources
func (p *NexusDashboardProvider) Resources(_ context.Context) []func() resource.Resource {
	resources := []func() resource.Resource{}
	resources = append(resources, manage.GetResources()...)
	resources = append(resources, onemanage.GetResources()...)  // Add this line
	return resources
}
```

### Step 7: Import for Side-Effects (`provider/provider.go`)

Add blank import to trigger resource registration:

```go
import (
	// ... other imports ...
	
	_ "terraform-provider-nd/internal/manage/resource_fabric_vxlan"
	_ "terraform-provider-nd/internal/onemanage/resource_example"  // Add this
)
```

## Important Concepts

### 1. Shared API Client

All modules receive the **same** `*nd.Client` instance:

```go
// Provider creates one client
client, err := nd.NewClient(url, basePath, username, password, ...)

// All modules receive the same client
ndClient.NDModules[manage.ModuleKey] = manage.NewManage(&client)
ndClient.NDModules[onemanage.ModuleKey] = onemanage.NewClient(&client)
```

**Benefits:**
- Connection pooling works correctly
- Rate limiting is shared across modules
- Authentication state is shared
- More efficient resource usage

### 2. Registry Pattern

A **registry** stores resource factories:

```go
// Resource factory function
type ResourceFactory = func() resource.Resource

// Example factory
func NewExampleResource() resource.Resource {
	return &exampleResource{}  // Creates new instance
}

// Auto-registration
func init() {
	registry.RegisterResource("onemanage", NewExampleResource)
}
```

The factory function is **stored** in the registry and **called** when needed.

### 3. Eager Initialization

Modules are created **during provider configuration**:

```go
// Provider.Configure() creates all modules upfront
ndClient.NDModules[manage.ModuleKey] = manage.NewManage(&client)
ndClient.NDModules[onemanage.ModuleKey] = onemanage.NewClient(&client)
```

**Benefits:**
- Simple code path
- Early error detection
- All modules available immediately
- Predictable startup time

### 4. Avoiding Cyclic Imports

**❌ DON'T:**
```go
// In onemanage/manage.go
import "terraform-provider-nd/internal/provider"  // Creates cycle!

type OneManageClient struct {
	ProviderClient *provider.NDClient  // Bad!
}
```

**✅ DO:**
```go
// In resource file
import "terraform-provider-nd/internal/registry"

// Use interface, not concrete type
client, ok := req.ProviderData.(registry.ClientProvider)
```

## Checklist

- [ ] Created `internal/onemanage/manage.go` with `NewClient(*nd.Client)`
- [ ] Created `internal/onemanage/register.go`
- [ ] Created resource packages with `init.go`
- [ ] Implemented resources using `registry.ClientProvider`
- [ ] Added module to `provider.go` Configure method
- [ ] Added module to `DataSources()` and `Resources()` functions
- [ ] Added blank import in `provider.go`
- [ ] Tested that resources work correctly
- [ ] Verified shared client is used by all modules

## Testing Shared Client

Add logging to verify client sharing:

```go
func NewClient(client *nd.Client) *OneManageClient {
	log.Printf("🔗 OneManage module got client: %p", client)
	// ... rest of implementation
}
```

Run Terraform and check that all modules log the **same pointer address**.

## Common Pitfalls

1. **Forgetting `init.go`**: Resources won't auto-register
2. **Wrong ModuleKey**: Must match between resource and module
3. **Missing blank import**: Resource `init()` never runs
4. **Importing provider package**: Creates cyclic import
5. **Creating separate clients**: Defeats shared client benefits

## Example: Complete Module

See `internal/manage/` for a complete working example of this pattern.

## Module Comparison

| Feature | Current Architecture | Factory Pattern |
|---------|---------------------|-----------------|
| Client Sharing | ✅ Shared | ✅ Shared |
| Module Creation | Eager (startup) | Lazy (on first use) |
| Complexity | Simple | More complex |
| Error Handling | Early (provider config) | Late (resource config) |
| Memory Usage | All modules loaded | Only used modules |

The current architecture prioritizes **simplicity and shared resources** over lazy loading optimization.

## Questions?

For questions or issues, refer to the existing `internal/manage/` module as a reference implementation.
