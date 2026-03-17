// Code generated;  DO NOT EDIT.

package resource_vpc_pair

import (
	"strconv"
	"terraform-provider-nd/internal/manage/resource_vpc_pair"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func VpcPairModelHelperStateCheck(RscName string, c resource_vpc_pair.NDFCVpcPairModel, attrPath path.Path) []resource.TestCheckFunc {
	ret := []resource.TestCheckFunc{}

	if c.FabricName != "" {
		ret = append(ret, resource.TestCheckResourceAttr(RscName, attrPath.AtName("fabric_name").String(), c.FabricName))
	}
	if c.PeerSwitchId != "" {
		ret = append(ret, resource.TestCheckResourceAttr(RscName, attrPath.AtName("peer_switch_id").String(), c.PeerSwitchId))
	}
	if c.SwitchId != "" {
		ret = append(ret, resource.TestCheckResourceAttr(RscName, attrPath.AtName("switch_id").String(), c.SwitchId))
	}
	if c.UseVirtualPeerlink != nil {
		ret = append(ret, resource.TestCheckResourceAttr(RscName, attrPath.AtName("use_virtual_peerlink").String(), strconv.FormatBool(*c.UseVirtualPeerlink)))
	}

	if c.Deploy {
		ret = append(ret, resource.TestCheckResourceAttr(RscName, attrPath.AtName("deploy").String(), "true"))
	} else {
		ret = append(ret, resource.TestCheckResourceAttr(RscName, attrPath.AtName("deploy").String(), "false"))
	}
	return ret
}
