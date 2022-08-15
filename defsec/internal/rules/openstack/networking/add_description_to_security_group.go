package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckSecurityGroupHasDescription = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-OPNSTK-0005",
		Provider:    providers2.OpenStackProvider,
		Service:     "networking",
		ShortCode:   "describe-security-group",
		Summary:     "Missing description for security group.",
		Impact:      "Auditing capability and awareness limited.",
		Resolution:  "Add descriptions for all security groups",
		Explanation: `Security groups should include a description for auditing purposes. Simplifies auditing, debugging, and managing security groups.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformSecurityGroupHasDescriptionGoodExamples,
			BadExamples:         terraformSecurityGroupHasDescriptionBadExamples,
			Links:               terraformSecurityGroupHasDescriptionLinks,
			RemediationMarkdown: terraformSecurityGroupHasDescriptionRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, group := range s.OpenStack.Networking.SecurityGroups {
			if group.IsUnmanaged() {
				continue
			}
			if group.Description.IsEmpty() {
				results.Add(
					"Security group rule allows egress to multiple public addresses.",
					group.Description,
				)
			} else {
				results.AddPassed(group)
			}
		}
		return
	},
)
