package ecr

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
	"strings"
)

var CheckNoPublicAccess = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0032",
		Provider:    providers2.AWSProvider,
		Service:     "ecr",
		ShortCode:   "no-public-access",
		Summary:     "ECR repository policy must block public access",
		Impact:      "Risk of potential data leakage of sensitive artifacts",
		Resolution:  "Do not allow public access in the policy",
		Explanation: `Allowing public access to the ECR repository risks leaking sensitive of abusable information`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-policies.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicAccessGoodExamples,
			BadExamples:         cloudFormationNoPublicAccessBadExamples,
			Links:               cloudFormationNoPublicAccessLinks,
			RemediationMarkdown: cloudFormationNoPublicAccessRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, repo := range s.AWS.ECR.Repositories {
			if repo.IsUnmanaged() {
				continue
			}
			for _, policyDocument := range repo.Policies {
				policy := policyDocument.Document.Parsed
				statements, _ := policy.Statements()
				for _, statement := range statements {
					var hasECRAction bool
					actions, _ := statement.Actions()
					for _, action := range actions {
						if strings.HasPrefix(action, "ecr:") {
							hasECRAction = true
							break
						}
					}
					if !hasECRAction {
						continue
					}
					var foundIssue bool
					principals, _ := statement.Principals()
					if all, r := principals.All(); all {
						foundIssue = true
						results.Add(
							"Policy provides public access to the ECR repository.",
							policyDocument.Document.MetadataFromIamGo(statement.Range(), r),
						)
					} else {
						accounts, r := principals.AWS()
						for _, account := range accounts {
							if account == "*" {
								foundIssue = true
								results.Add(
									"Policy provides public access to the ECR repository.",
									policyDocument.Document.MetadataFromIamGo(statement.Range(), r),
								)
							}
							continue
						}
					}
					if foundIssue {
						results.AddPassed(&repo)
					}
				}
			}
		}
		return
	},
)
