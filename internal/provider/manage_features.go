package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func GetManageResources() []func() resource.Resource {
	return []func() resource.Resource{
		NewFabricVxlanResource,
		// Add resources here
		// NewFabricVxlanResource, // Will be added when implementation is ready
	}
}

func GetManageDataSources() []func() datasource.DataSource {
	return []func() datasource.DataSource{
		// Add data sources here
	}
}