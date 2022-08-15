package iam

import (
	"fmt"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	iam2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/iam"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
	"strings"

	"github.com/liamg/iamgo"
)

var CheckNoPolicyWildcards = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0057",
		Provider:    providers2.AWSProvider,
		Service:     "iam",
		ShortCode:   "no-policy-wildcards",
		Summary:     "IAM policy should avoid use of wildcards and instead apply the principle of least privilege",
		Impact:      "Overly permissive policies may grant access to sensitive resources",
		Resolution:  "Specify the exact permissions required, and to which resources they should apply instead of using wildcards.",
		Explanation: `You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPolicyWildcardsGoodExamples,
			BadExamples:         terraformNoPolicyWildcardsBadExamples,
			Links:               terraformNoPolicyWildcardsLinks,
			RemediationMarkdown: terraformNoPolicyWildcardsRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationNoPolicyWildcardsGoodExamples,
			BadExamples:         cloudFormationNoPolicyWildcardsBadExamples,
			Links:               cloudFormationNoPolicyWildcardsLinks,
			RemediationMarkdown: cloudFormationNoPolicyWildcardsRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, policy := range s.AWS.IAM.Policies {
			results = checkPolicy(policy.Document, results)
		}
		for _, group := range s.AWS.IAM.Groups {
			for _, policy := range group.Policies {
				results = checkPolicy(policy.Document, results)
			}
		}
		for _, user := range s.AWS.IAM.Users {
			for _, policy := range user.Policies {
				results = checkPolicy(policy.Document, results)
			}
		}
		for _, role := range s.AWS.IAM.Roles {
			for _, policy := range role.Policies {
				results = checkPolicy(policy.Document, results)
			}
		}
		return results
	},
)

func checkPolicy(src iam2.Document, results scan2.Results) scan2.Results {
	statements, _ := src.Parsed.Statements()
	for _, statement := range statements {
		results = checkStatement(src, statement, results)
	}
	return results
}

//nolint
func checkStatement(src iam2.Document, statement iamgo.Statement, results scan2.Results) scan2.Results {
	effect, _ := statement.Effect()
	if effect != iamgo.EffectAllow {
		return results
	}

	actions, r := statement.Actions()
	for _, action := range actions {
		if strings.Contains(action, "*") {
			results.Add(
				fmt.Sprintf(
					"IAM policy document uses wildcarded action '%s'",
					actions[0],
				),
				src.MetadataFromIamGo(statement.Range(), r),
			)
		} else {
			results.AddPassed(src)
		}
	}

	resources, r := statement.Resources()
	for _, resource := range resources {
		if strings.Contains(resource, "*") {
			if allowed, action := iam2.IsWildcardAllowed(actions...); !allowed {
				if strings.HasSuffix(resource, "/*") && strings.HasPrefix(resource, "arn:aws:s3") {
					continue
				}
				results.Add(
					fmt.Sprintf("IAM policy document uses sensitive action '%s' on wildcarded resource '%s'", action, resources[0]),
					src.MetadataFromIamGo(statement.Range(), r),
				)
			} else {
				results.AddPassed(src)
			}
		} else {
			results.AddPassed(src)
		}
	}
	principals, _ := statement.Principals()
	if all, r := principals.All(); all {
		results.Add(
			"IAM policy document uses wildcarded principal.",
			src.MetadataFromIamGo(statement.Range(), r),
		)
	}
	aws, r := principals.AWS()
	for _, principal := range aws {
		if strings.Contains(principal, "*") {
			results.Add(
				"IAM policy document uses wildcarded principal.",
				src.MetadataFromIamGo(statement.Range(), r),
			)
		} else {
			results.AddPassed(src)
		}
	}

	return results
}
