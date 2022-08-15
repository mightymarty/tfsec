package config

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAggregateAllRegions = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0019",
		Provider:   providers2.AWSProvider,
		Service:    "config",
		ShortCode:  "aggregate-all-regions",
		Summary:    "Config configuration aggregator should be using all regions for source",
		Impact:     "Sources that aren't covered by the aggregator are not include in the configuration",
		Resolution: "Set the aggregator to cover all regions",
		Explanation: `The configuration aggregator should be configured with all_regions for the source. 

This will help limit the risk of any unmonitored configuration in regions that are thought to be unused.`,
		Links: []string{
			"https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformAggregateAllRegionsGoodExamples,
			BadExamples:         terraformAggregateAllRegionsBadExamples,
			Links:               terraformAggregateAllRegionsLinks,
			RemediationMarkdown: terraformAggregateAllRegionsRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationAggregateAllRegionsGoodExamples,
			BadExamples:         cloudFormationAggregateAllRegionsBadExamples,
			Links:               cloudFormationAggregateAllRegionsLinks,
			RemediationMarkdown: cloudFormationAggregateAllRegionsRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		if !s.AWS.Config.ConfigurationAggregrator.IsDefined {
			return
		}
		if s.AWS.Config.ConfigurationAggregrator.SourceAllRegions.IsFalse() {
			results.Add(
				"Configuration aggregation is not set to source from all regions.",
				s.AWS.Config.ConfigurationAggregrator.SourceAllRegions,
			)
		} else {
			results.AddPassed(s.AWS.Config.ConfigurationAggregrator.SourceAllRegions)
		}
		return
	},
)
