package monitor

import (
	"fmt"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	monitor2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/monitor"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
	"strings"
)

var CheckCaptureAllRegions = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0032",
		Provider:    providers2.AzureProvider,
		Service:     "monitor",
		ShortCode:   "capture-all-regions",
		Summary:     "Ensure activitys are captured for all locations",
		Impact:      "Activity may be occurring in locations that aren't being monitored",
		Resolution:  "Enable capture for all locations",
		Explanation: `Log profiles should capture all regions to ensure that all events are logged`,
		Links: []string{
			"https://docs.microsoft.com/en-us/cli/azure/monitor/log-profiles?view=azure-cli-latest#az_monitor_log_profiles_create-required-parameters",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformCaptureAllRegionsGoodExamples,
			BadExamples:         terraformCaptureAllRegionsBadExamples,
			Links:               terraformCaptureAllRegionsLinks,
			RemediationMarkdown: terraformCaptureAllRegionsRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, profile := range s.Azure.Monitor.LogProfiles {
			if missing := findMissingRegions(profile); len(missing) > 0 {
				details := fmt.Sprintf("%d regions missing", len(missing))
				if len(missing) < 10 {
					details = fmt.Sprintf("missing: %s", strings.Join(missing, ", "))
				}
				results.Add(
					fmt.Sprintf("Log profile does not log to all regions (%s).", details),
					&profile,
				)
			} else {
				results.AddPassed(&profile)
			}
		}
		return
	},
)

func findMissingRegions(profile monitor2.LogProfile) []string {
	var missing []string
	for _, location := range locations {
		var found bool
		for _, loc := range profile.Locations {
			if loc.EqualTo(location) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, location)
		}
	}
	return missing
}

var locations = []string{
	"eastus",
	"eastus2",
	"southcentralus",
	"westus2",
	"westus3",
	"australiaeast",
	"southeastasia",
	"northeurope",
	"swedencentral",
	"uksouth",
	"westeurope",
	"centralus",
	"northcentralus",
	"westus",
	"southafricanorth",
	"centralindia",
	"eastasia",
	"japaneast",
	"jioindiawest",
	"koreacentral",
	"canadacentral",
	"francecentral",
	"germanywestcentral",
	"norwayeast",
	"switzerlandnorth",
	"uaenorth",
	"brazilsouth",
	"centralusstage",
	"eastusstage",
	"eastus2stage",
	"northcentralusstage",
	"southcentralusstage",
	"westusstage",
	"westus2stage",
	"asia",
	"asiapacific",
	"australia",
	"brazil",
	"canada",
	"europe",
	"global",
	"india",
	"japan",
	"uk",
	"unitedstates",
	"eastasiastage",
	"southeastasiastage",
	"centraluseuap",
	"eastus2euap",
	"westcentralus",
	"southafricawest",
	"australiacentral",
	"australiacentral2",
	"australiasoutheast",
	"japanwest",
	"jioindiacentral",
	"koreasouth",
	"southindia",
	"westindia",
	"canadaeast",
	"francesouth",
	"germanynorth",
	"norwaywest",
	"swedensouth",
	"switzerlandwest",
	"ukwest",
	"uaecentral",
	"brazilsoutheast",
}
