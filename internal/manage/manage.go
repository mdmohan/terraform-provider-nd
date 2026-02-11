package manage

import (
	"github.com/netascode/go-nd"
)

// ModuleKey is the key used to register the manage module in the provider.
const ModuleKey = "manage"

type NexusDashboardManage struct {
	ApiClient *nd.Client
}

var manageInstance *NexusDashboardManage

func NewManage(client *nd.Client) *NexusDashboardManage {
	if manageInstance == nil {
		manageInstance = &NexusDashboardManage{
			ApiClient: client,
		}
	}
	return manageInstance
}
