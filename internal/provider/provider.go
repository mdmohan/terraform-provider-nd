package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"terraform-provider-nd/internal/provider/provider/provider_nd"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces
var (
	_ provider.Provider = &NexusDashboardProvider{}
)

// NexusDashboardProvider is the provider implementation.
type NexusDashboardProvider struct {
	// version is set to the provider version on release.
	version string
}

// NDClient represents the Nexus Dashboard client
type NDClient struct {
	URL      string
	Username string
	Password string
	Domain   string
	Insecure bool
	Timeout  time.Duration
	Client   *http.Client
}

// New returns a function that initializes and returns a new NexusDashboardProvider.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &NexusDashboardProvider{
			version: version,
		}
	}
}

// Metadata returns the provider type name.
func (p *NexusDashboardProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "nd"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data.
func (p *NexusDashboardProvider) Schema(ctx context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = provider_nd.NdProviderSchema(ctx)
}

// Configure prepares a Nexus Dashboard API client for data sources and resources.
func (p *NexusDashboardProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// Retrieve provider data from configuration
	var config provider_nd.NdModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If practitioner provided a configuration value for any of the
	// attributes, it must be a known value.

	if config.Url.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("url"),
			"Unknown Nexus Dashboard URL",
			"The provider cannot create the Nexus Dashboard API client as there is an unknown configuration value for the URL. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the NDFC_URL environment variable.",
		)
	}

	if config.Username.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("username"),
			"Unknown Nexus Dashboard Username",
			"The provider cannot create the Nexus Dashboard API client as there is an unknown configuration value for the username. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the NDFC_USER environment variable.",
		)
	}

	if config.Password.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("password"),
			"Unknown Nexus Dashboard Password",
			"The provider cannot create the Nexus Dashboard API client as there is an unknown configuration value for the password. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the NDFC_PASSWORD environment variable.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Default values to environment variables, but override
	// with Terraform configuration value if set.

	url := os.Getenv("NDFC_URL")
	username := os.Getenv("NDFC_USER")
	password := os.Getenv("NDFC_PASSWORD")
	domain := os.Getenv("NDFC_DOMAIN")
	insecureStr := os.Getenv("NDFC_INSECURE")
	timeoutStr := os.Getenv("NDFC_TIMEOUT")

	if !config.Url.IsNull() {
		url = config.Url.ValueString()
	}

	if !config.Username.IsNull() {
		username = config.Username.ValueString()
	}

	if !config.Password.IsNull() {
		password = config.Password.ValueString()
	}

	if !config.Domain.IsNull() {
		domain = config.Domain.ValueString()
	}

	var insecure bool
	if !config.Insecure.IsNull() {
		insecure = config.Insecure.ValueBool()
	} else if insecureStr != "" {
		var err error
		insecure, err = strconv.ParseBool(insecureStr)
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("insecure"),
				"Invalid Insecure Value",
				"The provider cannot parse the insecure value from environment variable NDFC_INSECURE. "+
					"Expected 'true' or 'false', got: "+insecureStr,
			)
			return
		}
	}

	var timeout time.Duration = 60 * time.Second // Default timeout
	if !config.Timeout.IsNull() {
		timeout = time.Duration(config.Timeout.ValueInt64()) * time.Second
	} else if timeoutStr != "" {
		timeoutInt, err := strconv.ParseInt(timeoutStr, 10, 64)
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("timeout"),
				"Invalid Timeout Value",
				"The provider cannot parse the timeout value from environment variable NDFC_TIMEOUT. "+
					"Expected an integer, got: "+timeoutStr,
			)
			return
		}
		timeout = time.Duration(timeoutInt) * time.Second
	}

	// If any of the expected configurations are missing, return
	// errors with provider-specific guidance.

	if url == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("url"),
			"Missing Nexus Dashboard URL",
			"The provider requires a URL to connect to the Nexus Dashboard. "+
				"Set the url value in the provider configuration or use the NDFC_URL environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if username == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("username"),
			"Missing Nexus Dashboard Username",
			"The provider requires a username to authenticate with the Nexus Dashboard. "+
				"Set the username value in the provider configuration or use the NDFC_USER environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if password == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("password"),
			"Missing Nexus Dashboard Password",
			"The provider requires a password to authenticate with the Nexus Dashboard. "+
				"Set the password value in the provider configuration or use the NDFC_PASSWORD environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "nd_url", url)
	ctx = tflog.SetField(ctx, "nd_username", username)
	ctx = tflog.SetField(ctx, "nd_domain", domain)
	ctx = tflog.SetField(ctx, "nd_insecure", insecure)
	ctx = tflog.SetField(ctx, "nd_timeout", timeout)
	ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "nd_password")

	tflog.Debug(ctx, "Creating Nexus Dashboard client")

	// Create a new Nexus Dashboard client using the configuration values
	client, err := NewNDClient(&NDClientConfig{
		URL:      url,
		Username: username,
		Password: password,
		Domain:   domain,
		Insecure: insecure,
		Timeout:  timeout,
	})

	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create Nexus Dashboard API Client",
			"An unexpected error occurred when creating the Nexus Dashboard API client. "+
				"If the error is not clear, please contact the provider developers.\n\n"+
				"Nexus Dashboard Client Error: "+err.Error(),
		)
		return
	}

	// Make the Nexus Dashboard client available during DataSource and Resource
	// type Configure methods.
	resp.DataSourceData = client
	resp.ResourceData = client

	tflog.Info(ctx, "Configured Nexus Dashboard client", map[string]any{"success": true})
}

// DataSources defines the data sources implemented in the provider.
func (p *NexusDashboardProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		// Add data sources here
	}
}

// Resources defines the resources implemented in the provider.
func (p *NexusDashboardProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		// Add resources here
		// NewFabricVxlanResource, // TODO: Add when ready
	}
}

// NDClientConfig holds the configuration for creating an ND client
type NDClientConfig struct {
	URL      string
	Username string
	Password string
	Domain   string
	Insecure bool
	Timeout  time.Duration
}

// NewNDClient creates a new Nexus Dashboard client
func NewNDClient(config *NDClientConfig) (*NDClient, error) {
	client := &NDClient{
		URL:      config.URL,
		Username: config.Username,
		Password: config.Password,
		Domain:   config.Domain,
		Insecure: config.Insecure,
		Timeout:  config.Timeout,
	}

	// Create HTTP client with appropriate settings
	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	if config.Insecure {
		// TODO: Add TLS configuration for insecure connections
		// This would typically involve setting up a custom transport
		// with TLS settings that skip certificate verification
	}

	client.Client = httpClient

	// TODO: Add authentication logic here
	// This would typically involve making a login request to get an authentication token

	return client, nil
}

// Additional methods for the NDClient can be added here
// For example: Login, Logout, MakeRequest, etc.

// Login authenticates with the Nexus Dashboard
func (c *NDClient) Login(ctx context.Context) error {
	// TODO: Implement authentication logic
	tflog.Debug(ctx, "Authenticating with Nexus Dashboard", map[string]any{
		"url":      c.URL,
		"username": c.Username,
		"domain":   c.Domain,
	})

	// This is a placeholder - actual implementation would make HTTP requests
	// to authenticate with the Nexus Dashboard API

	return nil
}

// MakeRequest is a helper method for making HTTP requests to the Nexus Dashboard API
func (c *NDClient) MakeRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	// TODO: Implement HTTP request logic
	// This would handle the actual HTTP communication with the ND API

	tflog.Debug(ctx, "Making request to Nexus Dashboard", map[string]any{
		"method": method,
		"path":   path,
	})

	return nil, fmt.Errorf("not implemented")
}
