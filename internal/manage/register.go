package manage

import (
	"terraform-provider-nd/internal/manage/resources/resource_fabric_vxlan"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// GetResources returns all resources for the manage module.
// Each team maintains their own register.go - minimizes merge conflicts.
func GetResources() []func() resource.Resource {
	return []func() resource.Resource{
		resource_fabric_vxlan.NewFabricVxlanResource,
		// Add more manage resources here
	}
}

// GetDataSources returns all data sources for the manage module.
func GetDataSources() []func() datasource.DataSource {
	return []func() datasource.DataSource{
		// Add manage data sources here
	}
}
