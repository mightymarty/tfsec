package azure

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/appservice"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/authorization"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/compute"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/container"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/database"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/datafactory"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/datalake"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/keyvault"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/monitor"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/network"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/securitycenter"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/storage"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure/synapse"
)

type Azure struct {
	types.Metadata
	AppService     appservice.AppService
	Authorization  authorization.Authorization
	Compute        compute.Compute
	Container      container.Container
	Database       database.Database
	DataFactory    datafactory.DataFactory
	DataLake       datalake.DataLake
	KeyVault       keyvault.KeyVault
	Monitor        monitor.Monitor
	Network        network.Network
	SecurityCenter securitycenter.SecurityCenter
	Storage        storage.Storage
	Synapse        synapse.Synapse
}
