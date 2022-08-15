package ecs

import (
	"fmt"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	"github.com/mightymarty/tfsec/defsec/internal/security"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"

	"github.com/owenrumney/squealer/pkg/squealer"
)

var CheckNoPlaintextSecrets = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0036",
		Provider:    providers2.AWSProvider,
		Service:     "ecs",
		ShortCode:   "no-plaintext-secrets",
		Summary:     "Task definition defines sensitive environment variable(s).",
		Impact:      "Sensitive data could be exposed in the AWS Management Console",
		Resolution:  "Use secrets for the task definition",
		Explanation: `You should not make secrets available to a user in plaintext in any scenario. Secrets can instead be pulled from a secure secret storage system by the service requiring them.`,
		Links: []string{
			"https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html",
			"https://www.vaultproject.io/",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPlaintextSecretsGoodExamples,
			BadExamples:         terraformNoPlaintextSecretsBadExamples,
			Links:               terraformNoPlaintextSecretsLinks,
			RemediationMarkdown: terraformNoPlaintextSecretsRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationNoPlaintextSecretsGoodExamples,
			BadExamples:         cloudFormationNoPlaintextSecretsBadExamples,
			Links:               cloudFormationNoPlaintextSecretsLinks,
			RemediationMarkdown: cloudFormationNoPlaintextSecretsRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {

		scanner := squealer.NewStringScanner()

		for _, definition := range s.AWS.ECS.TaskDefinitions {
			for _, container := range definition.ContainerDefinitions {
				for _, env := range container.Environment {
					if result := scanner.Scan(env.Value); result.TransgressionFound || security.IsSensitiveAttribute(env.Name) {
						results.Add(
							fmt.Sprintf("Container definition contains a potentially sensitive environment variable '%s': %s", env.Name, result.Description),
							container,
						)
					} else {
						results.AddPassed(&definition)
					}
				}
			}
		}
		return
	},
)
