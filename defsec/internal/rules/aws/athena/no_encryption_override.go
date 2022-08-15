package athena

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoEncryptionOverride = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0007",
		Provider:    providers2.AWSProvider,
		Service:     "athena",
		ShortCode:   "no-encryption-override",
		Summary:     "Athena workgroups should enforce configuration to prevent client disabling encryption",
		Impact:      "Clients can ignore encryption requirements",
		Resolution:  "Enforce the configuration to prevent client overrides",
		Explanation: `Athena workgroup configuration should be enforced to prevent client side changes to disable encryption settings.`,
		Links: []string{
			"https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoEncryptionOverrideGoodExamples,
			BadExamples:         terraformNoEncryptionOverrideBadExamples,
			Links:               terraformNoEncryptionOverrideLinks,
			RemediationMarkdown: terraformNoEncryptionOverrideRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationNoEncryptionOverrideGoodExamples,
			BadExamples:         cloudFormationNoEncryptionOverrideBadExamples,
			Links:               cloudFormationNoEncryptionOverrideLinks,
			RemediationMarkdown: cloudFormationNoEncryptionOverrideRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, workgroup := range s.AWS.Athena.Workgroups {
			if workgroup.IsUnmanaged() {
				continue
			}
			if workgroup.EnforceConfiguration.IsFalse() {
				results.Add(
					"The workgroup configuration is not enforced.",
					workgroup.EnforceConfiguration,
				)
			}
		}
		return
	},
)
