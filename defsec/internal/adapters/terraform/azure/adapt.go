package azure

import (
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/appservice"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/authorization"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/compute"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/container"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/database"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/datafactory"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/datalake"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/keyvault"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/monitor"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/network"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/securitycenter"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/storage"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure/synapse"
	azure2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) azure2.Azure {
	return azure2.Azure{
		AppService:     appservice.Adapt(modules),
		Authorization:  authorization.Adapt(modules),
		Compute:        compute.Adapt(modules),
		Container:      container.Adapt(modules),
		Database:       database.Adapt(modules),
		DataFactory:    datafactory.Adapt(modules),
		DataLake:       datalake.Adapt(modules),
		KeyVault:       keyvault.Adapt(modules),
		Monitor:        monitor.Adapt(modules),
		Network:        network.Adapt(modules),
		SecurityCenter: securitycenter.Adapt(modules),
		Storage:        storage.Adapt(modules),
		Synapse:        synapse.Adapt(modules),
	}
}
