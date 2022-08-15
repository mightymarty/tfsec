package securitycenter

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	securitycenter2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/securitycenter"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableStandardSubscription = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0045",
		Provider:   providers2.AzureProvider,
		Service:    "security-center",
		ShortCode:  "enable-standard-subscription",
		Summary:    "Enable the standard security center subscription tier",
		Impact:     "Using free subscription does not enable Azure Defender for the resource type",
		Resolution: "Enable standard subscription tier to benefit from Azure Defender",
		Explanation: `To benefit from Azure Defender you should use the Standard subscription tier.
			
			Enabling Azure Defender extends the capabilities of the free mode to workloads running in private and other public clouds, providing unified security management and threat protection across your hybrid cloud workloads.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/security-center/security-center-pricing",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableStandardSubscriptionGoodExamples,
			BadExamples:         terraformEnableStandardSubscriptionBadExamples,
			Links:               terraformEnableStandardSubscriptionLinks,
			RemediationMarkdown: terraformEnableStandardSubscriptionRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, sub := range s.Azure.SecurityCenter.Subscriptions {
			if sub.IsUnmanaged() {
				continue
			}
			if sub.Tier.EqualTo(securitycenter2.TierFree) {
				results.Add(
					"Security center subscription uses the free tier.",
					sub.Tier,
				)
			} else {
				results.AddPassed(&sub)
			}
		}
		return
	},
)
