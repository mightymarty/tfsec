package sam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoStateMachinePolicyWildcards = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0120",
		Provider:    providers2.AWSProvider,
		Service:     "sam",
		ShortCode:   "no-state-machine-policy-wildcards",
		Summary:     "State machine policies should avoid use of wildcards and instead apply the principle of least privilege",
		Impact:      "Overly permissive policies may grant access to sensitive resources",
		Resolution:  "Specify the exact permissions required, and to which resources they should apply instead of using wildcards.",
		Explanation: `You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-policies",
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationNoStateMachinePolicyWildcardsGoodExamples,
			BadExamples:         cloudFormationNoStateMachinePolicyWildcardsBadExamples,
			Links:               cloudFormationNoStateMachinePolicyWildcardsLinks,
			RemediationMarkdown: cloudFormationNoStateMachinePolicyWildcardsRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {

		for _, stateMachine := range s.AWS.SAM.StateMachines {
			if stateMachine.IsUnmanaged() {
				continue
			}

			for _, document := range stateMachine.Policies {
				policy := document.Document.Parsed
				statements, _ := policy.Statements()
				for _, statement := range statements {
					results = checkStatement(document.Document, statement, results)
				}
			}
		}
		return
	},
)
