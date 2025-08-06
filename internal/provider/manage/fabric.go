package manage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"terraform-provider-nd/internal/provider/manage/api"
	"terraform-provider-nd/internal/provider/schema/resources/resource_fabric_vxlan"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// RscCreateFabric creates a fabric resource using the VXLAN fabric model
func (m *NexusDashboardManage) RscCreateFabric(ctx context.Context, dg *diag.Diagnostics, input *resource_fabric_vxlan.FabricVxlanModel) {
	if input == nil {
		dg.AddError(
			"Invalid Input",
			"The input model is nil",
		)
		return
	}

	inData := input.GetModelData()

	log.Printf("Creating fabric %s with category %s", inData.FabricName, inData.Category)

	// Create fabric API client
	fabricAPI := api.NewFabricAPI(nil, m.ApiClient)

	// Convert model data to JSON
	fabricPayload, err := json.Marshal(inData)
	if err != nil {
		dg.AddError(
			"Error Creating Fabric",
			fmt.Sprintf("Could not create fabric, Data Marshall error: %v", err),
		)
		return
	}

	// Call the API to create the fabric
	res, err := fabricAPI.Post(fabricPayload)
	if err != nil {
		dg.AddError(
			"Error Creating Fabric",
			fmt.Sprintf("Could not create fabric, unexpected error: %v %v", err, res),
		)
		return
	}
	// Read the created fabric
	// ND BUG - license_tier is not set in the response. Try delaying the read
	time.Sleep(2 * time.Second)
	m.RscGetFabric(ctx, dg, input)

}

// GetFabric retrieves fabric information by name
func (m *NexusDashboardManage) RscGetFabric(ctx context.Context, dg *diag.Diagnostics, in *resource_fabric_vxlan.FabricVxlanModel) {

	fabricAPI := api.NewFabricAPI(nil, m.ApiClient)
	fabricAPI.FabricName = in.FabricName.ValueString()
	respData, err := fabricAPI.Get()
	if err != nil {
		dg.AddError(
			"Error Creating Fabric",
			fmt.Sprintf("Could not read fabric, unexpected error: %v %v", err, respData),
		)
		return
	}
	var outData resource_fabric_vxlan.NDFCFabricVxlanModel

	err = json.Unmarshal(respData, &outData)
	if err != nil {
		dg.AddError(
			"Error Creating Fabric",
			fmt.Sprintf("Could not read fabric, unexpected error: %v %v", err, respData),
		)
		return
	}
	log.Printf("Location = %v %v", *outData.Location.Latitude, *outData.Location.Longitude)
	log.Printf("Netflow = %v", *outData.Management.NetflowSettings.Netflow)
	in.SetModelData(&outData)
	log.Printf("Location from model=%v,%v", in.Location.Latitude.ValueFloat64(), in.Location.Longitude.ValueFloat64())
}

// UpdateFabricEVPN updates a fabric with the provided payload
func (m *NexusDashboardManage) RscUpdateFabric(ctx context.Context, dg *diag.Diagnostics, fabricModel *resource_fabric_vxlan.FabricVxlanModel) {
	inData := fabricModel.GetModelData()
	log.Printf("Creating fabric %s with category %s", inData.FabricName, inData.Category)

	fabricAPI := api.NewFabricAPI(nil, m.ApiClient)
	fabricAPI.FabricName = inData.FabricName

	inDataBytes, err := json.Marshal(inData)
	if err != nil {
		dg.AddError(
			"Error Updating Fabric",
			fmt.Sprintf("Could not update fabric, Data Marshall error: %v", err),
		)
		tflog.Error(ctx, "Error Updating Fabric", map[string]interface{}{"error": err.Error()})
		return
	}
	res, err := fabricAPI.Put(inDataBytes)
	if err != nil {
		dg.AddError(
			"Error Updating Fabric",
			fmt.Sprintf("Could not update fabric, unexpected error: %v %v", err, res),
		)
		tflog.Error(ctx, "Error Updating Fabric", map[string]interface{}{"error": err.Error()})
		return
	}
	// Read the updated fabric
	m.RscGetFabric(ctx, dg, fabricModel)
	log.Printf("Updated fabric %s with category %s", inData.FabricName, inData.Category)

}

// DeleteFabricEVPN deletes a fabric by name
func (m *NexusDashboardManage) RscDeleteFabric(ctx context.Context, dg *diag.Diagnostics, fabricName string) {
	fabricAPI := api.NewFabricAPI(nil, m.ApiClient)
	fabricAPI.FabricName = fabricName
	res, err := fabricAPI.Delete()
	if err != nil {
		dg.AddError(
			"Error Deleting Fabric",
			fmt.Sprintf("Could not delete fabric, unexpected error: %v %v", err, res),
		)
		tflog.Error(ctx, "Error Deleting Fabric", map[string]interface{}{"error": err.Error()})
		return
	}
}
