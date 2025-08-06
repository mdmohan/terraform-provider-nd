package provider

import (
	"context"
	"fmt"
	"terraform-provider-nd/internal/provider/manage"
	"terraform-provider-nd/internal/provider/schema/resources/resource_fabric_vxlan"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces
var (
	_ resource.Resource              = &fabricVxlanResource{}
	_ resource.ResourceWithConfigure = &fabricVxlanResource{}
)

// NewFabricVxlanResource is a helper function to simplify the provider implementation.
func NewFabricVxlanResource() resource.Resource {
	return &fabricVxlanResource{}
}

// fabricVxlanResource is the resource implementation.
type fabricVxlanResource struct {
	client *NDClient
}

// Metadata returns the resource type name.
func (r *fabricVxlanResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fabric_vxlan"
}

// Schema defines the schema for the resource.
func (r *fabricVxlanResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = resource_fabric_vxlan.FabricVxlanResourceSchema(ctx)
}

// Configure adds the provider configured client to the resource.
func (r *fabricVxlanResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*NDClient)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

// Create creates the resource and sets the initial Terraform state.
func (r *fabricVxlanResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var in resource_fabric_vxlan.FabricVxlanModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &in)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating Fabric VXLAN", map[string]interface{}{
		"fabric_name": in.FabricName.ValueString(),
	})

	manageInstance := r.client.NDModules["manage"].(*manage.NexusDashboardManage)
	manageInstance.RscCreateFabric(ctx, &resp.Diagnostics, &in)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract the fabric ID from the response

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &in)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *fabricVxlanResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state resource_fabric_vxlan.FabricVxlanModel

	// Get current state
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading Fabric VXLAN", map[string]interface{}{
		"fabric_name": state.FabricName.ValueString(),
	})

	manageInstance := r.client.NDModules["manage"].(*manage.NexusDashboardManage)
	manageInstance.RscGetFabric(ctx, &resp.Diagnostics, &state)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *fabricVxlanResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan resource_fabric_vxlan.FabricVxlanModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating Fabric VXLAN", map[string]interface{}{
		"fabric_name": plan.FabricName.ValueString(),
	})

	manageInstance := r.client.NDModules["manage"].(*manage.NexusDashboardManage)
	manageInstance.RscUpdateFabric(ctx, &resp.Diagnostics, &plan)
	if resp.Diagnostics.HasError() {
		return
	}
	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *fabricVxlanResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state resource_fabric_vxlan.FabricVxlanModel

	// Get current state
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Deleting Fabric VXLAN", map[string]interface{}{
		"fabric_name": state.FabricName.ValueString(),
	})

	manageInstance := r.client.NDModules["manage"].(*manage.NexusDashboardManage)
	manageInstance.RscDeleteFabric(ctx, &resp.Diagnostics, state.FabricName.ValueString())
}
