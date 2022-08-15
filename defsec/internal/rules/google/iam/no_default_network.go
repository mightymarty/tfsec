package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoDefaultNetwork = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0010",
		Provider:    providers2.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-default-network",
		Summary:     "Default network should not be created at project level",
		Impact:      "Exposure of internal infrastructure/services to public internet",
		Resolution:  "Disable automatic default network creation",
		Explanation: `The default network which is provided for a project contains multiple insecure firewall rules which allow ingress to the project's infrastructure. Creation of this network should therefore be disabled.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoDefaultNetworkGoodExamples,
			BadExamples:         terraformNoDefaultNetworkBadExamples,
			Links:               terraformNoDefaultNetworkLinks,
			RemediationMarkdown: terraformNoDefaultNetworkRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		// TODO: check constraints before auto_create_network
		for _, project := range s.Google.IAM.AllProjects() {
			if project.IsUnmanaged() {
				continue
			}
			if project.AutoCreateNetwork.IsTrue() {
				results.Add(
					"Project has automatic network creation enabled.",
					project.AutoCreateNetwork,
				)
			} else {
				results.AddPassed(project)
			}
		}
		return
	},
)
