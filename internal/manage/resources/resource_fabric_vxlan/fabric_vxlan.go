package resource_fabric_vxlan

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ModuleKey is the key used to get the manage module from the provider.
const ModuleKey = "manage"

// Ensure the implementation satisfies the expected interfaces
var (
	_ resource.Resource              = &fabricVxlanResource{}
	_ resource.ResourceWithConfigure = &fabricVxlanResource{}
)

// ClientProvider is an interface that the main provider client implements.
type ClientProvider interface {
	GetModule(name string) interface{}
}

// ManageClient is the interface for manage module operations used by resources.
type ManageClient interface {
	RscCreateFabric(ctx context.Context, dg *diag.Diagnostics, input *FabricVxlanModel)
	RscGetFabric(ctx context.Context, dg *diag.Diagnostics, in *FabricVxlanModel)
	RscUpdateFabric(ctx context.Context, dg *diag.Diagnostics, fabricModel *FabricVxlanModel)
	RscDeleteFabric(ctx context.Context, dg *diag.Diagnostics, fabricName string)
}

// NewFabricVxlanResource is a helper function to simplify the provider implementation.
func NewFabricVxlanResource() resource.Resource {
	return &fabricVxlanResource{}
}

// fabricVxlanResource is the resource implementation.
type fabricVxlanResource struct {
	manageClient ManageClient
}

// Metadata returns the resource type name.
func (r *fabricVxlanResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fabric_vxlan"
}

// Schema defines the schema for the resource.
func (r *fabricVxlanResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = FabricVxlanResourceSchema(ctx)
}

// Configure adds the provider configured client to the resource.
func (r *fabricVxlanResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(ClientProvider)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected ClientProvider, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	manageModule := client.GetModule(ModuleKey)
	if manageModule == nil {
		resp.Diagnostics.AddError(
			"Manage Module Not Found",
			"The manage module was not registered with the provider.",
		)
		return
	}

	r.manageClient = manageModule.(ManageClient)
}

// Create creates the resource and sets the initial Terraform state.
func (r *fabricVxlanResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var in FabricVxlanModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &in)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating Fabric VXLAN", map[string]interface{}{
		"fabric_name": in.FabricName.ValueString(),
	})

	r.manageClient.RscCreateFabric(ctx, &resp.Diagnostics, &in)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &in)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *fabricVxlanResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state FabricVxlanModel

	// Get current state
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading Fabric VXLAN", map[string]interface{}{
		"fabric_name": state.FabricName.ValueString(),
	})

	r.manageClient.RscGetFabric(ctx, &resp.Diagnostics, &state)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *fabricVxlanResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan FabricVxlanModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating Fabric VXLAN", map[string]interface{}{
		"fabric_name": plan.FabricName.ValueString(),
	})

	r.manageClient.RscUpdateFabric(ctx, &resp.Diagnostics, &plan)
	if resp.Diagnostics.HasError() {
		return
	}
	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *fabricVxlanResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state FabricVxlanModel

	// Get current state
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Deleting Fabric VXLAN", map[string]interface{}{
		"fabric_name": state.FabricName.ValueString(),
	})

	r.manageClient.RscDeleteFabric(ctx, &resp.Diagnostics, state.FabricName.ValueString())
}
