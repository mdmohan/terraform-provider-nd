// Code generated;  DO NOT EDIT.

package resource_fabric_vxlan

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResourceFabricVxlan(t *testing.T) {
	type args struct {
		rscType  string
		rscName  string
		dataFile string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test_resource_fabric_vxlan",
			args: args{
				rscType:  "resource",
				rscName:  "fabric_vxlan",
				dataFile: "/examples/ndfc_payloads/data_fabric_vxlan.json",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name+"model_read", func(t *testing.T) {
			fileName := os.Getenv("GOPATH") + "/src/terraform-provider-ndfc" + tt.args.dataFile
			RsType := tt.args.rscType
			rscName := tt.args.rscName
			dataFromFile, err := os.ReadFile(fileName)
			if err != nil {
				t.Errorf("File read failure %v", err)
				return
			}
			modelData := NDFCFabricVxlanModel{}
			v := FabricVxlanModel{}

			err = json.Unmarshal(dataFromFile, &modelData)
			if err != nil {
				t.Errorf("Json Unmarshal failed %s_%s: %v", RsType, rscName, err)
			}
			if err := v.SetModelData(&modelData); err != nil {
				t.Errorf("SetModelData failed %s_%s: %v", RsType, rscName, err)
			}
			t.Logf("%s_%s Read and Set ok", RsType, rscName)

			var dataFromModel []byte

			modelDataRead := v.GetModelData()

			dataFromModel, err = json.Marshal(&modelDataRead)
			if err != nil {
				t.Errorf("Json marshal failed %s_%s: %v", RsType, rscName, err)
			}
			t.Logf("%s_%s Marshall ok", RsType, rscName)

			require.JSONEq(t, string(dataFromModel), string(dataFromFile))

		})
	}
}
