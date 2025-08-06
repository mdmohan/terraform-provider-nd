package manage

import (
	"github.com/netascode/go-nd"
)

type NexusDashboardManage struct {
	ApiClient *nd.Client
}

var manageInstance *NexusDashboardManage

func NewManage(client *nd.Client) interface{} {
	if manageInstance == nil {
		manageInstance = &NexusDashboardManage{
			ApiClient: client,
		}
	}
	return manageInstance
}
