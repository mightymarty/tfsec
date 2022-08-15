package google

import (
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/google/bigquery"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/google/compute"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/google/dns"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/google/gke"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/google/iam"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/google/kms"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/google/sql"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/google/storage"
	google2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) google2.Google {
	return google2.Google{
		BigQuery: bigquery.Adapt(modules),
		Compute:  compute.Adapt(modules),
		DNS:      dns.Adapt(modules),
		GKE:      gke.Adapt(modules),
		KMS:      kms.Adapt(modules),
		IAM:      iam.Adapt(modules),
		SQL:      sql.Adapt(modules),
		Storage:  storage.Adapt(modules),
	}
}
