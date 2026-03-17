// Code generated;  DO NOT EDIT.

package resource_vpc_pair

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type NDFCVpcPairModel struct {
	FabricName         string `json:"-"`
	PeerSwitchId       string `json:"peerSwitchId,omitempty"`
	SwitchId           string `json:"switchId,omitempty"`
	UseVirtualPeerlink *bool  `json:"useVirtualPeerLink,omitempty"`
	VpcAction          string `json:"vpcAction,omitempty"`
	Deploy             bool   `json:"-"`
}

func (v *VpcPairModel) SetModelData(jsonData *NDFCVpcPairModel) diag.Diagnostics {
	var err diag.Diagnostics
	err = nil

	if jsonData.FabricName != "" {
		v.FabricName = types.StringValue(jsonData.FabricName)
	} else {
		v.FabricName = types.StringNull()
	}

	if jsonData.PeerSwitchId != "" {
		v.PeerSwitchId = types.StringValue(jsonData.PeerSwitchId)
	} else {
		v.PeerSwitchId = types.StringNull()
	}

	if jsonData.SwitchId != "" {
		v.SwitchId = types.StringValue(jsonData.SwitchId)
	} else {
		v.SwitchId = types.StringNull()
	}

	if jsonData.UseVirtualPeerlink != nil {
		v.UseVirtualPeerlink = types.BoolValue(*jsonData.UseVirtualPeerlink)

	} else {
		v.UseVirtualPeerlink = types.BoolNull()
	}

	v.Deploy = types.BoolValue(jsonData.Deploy)

	return err
}

func (v VpcPairModel) GetModelData() *NDFCVpcPairModel {
	var data = new(NDFCVpcPairModel)

	//MARSHAL_BODY

	if !v.FabricName.IsNull() && !v.FabricName.IsUnknown() {
		data.FabricName = v.FabricName.ValueString()
	} else {
		data.FabricName = ""
	}

	if !v.PeerSwitchId.IsNull() && !v.PeerSwitchId.IsUnknown() {
		data.PeerSwitchId = v.PeerSwitchId.ValueString()
	} else {
		data.PeerSwitchId = ""
	}

	if !v.SwitchId.IsNull() && !v.SwitchId.IsUnknown() {
		data.SwitchId = v.SwitchId.ValueString()
	} else {
		data.SwitchId = ""
	}

	if !v.UseVirtualPeerlink.IsNull() && !v.UseVirtualPeerlink.IsUnknown() {
		data.UseVirtualPeerlink = new(bool)
		*data.UseVirtualPeerlink = v.UseVirtualPeerlink.ValueBool()
	} else {
		data.UseVirtualPeerlink = nil
	}

	if !v.Deploy.IsNull() && !v.Deploy.IsUnknown() {
		data.Deploy = v.Deploy.ValueBool()
	}

	return data
}
