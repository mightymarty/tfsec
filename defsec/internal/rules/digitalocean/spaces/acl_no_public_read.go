package spaces

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAclNoPublicRead = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-DIG-0006",
		Provider:    providers2.DigitalOceanProvider,
		Service:     "spaces",
		ShortCode:   "acl-no-public-read",
		Summary:     "Spaces bucket or bucket object has public read acl set",
		Impact:      "The contents of the space can be accessed publicly",
		Resolution:  "Apply a more restrictive ACL",
		Explanation: `Space bucket and bucket object permissions should be set to deny public access unless explicitly required.`,
		Links: []string{
			"https://docs.digitalocean.com/reference/api/spaces-api/#access-control-lists-acls",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformAclNoPublicReadGoodExamples,
			BadExamples:         terraformAclNoPublicReadBadExamples,
			Links:               terraformAclNoPublicReadLinks,
			RemediationMarkdown: terraformAclNoPublicReadRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.DigitalOcean.Spaces.Buckets {
			if bucket.IsUnmanaged() {
				continue
			}
			if bucket.ACL.EqualTo("public-read") {
				results.Add(
					"Bucket is publicly exposed.",
					bucket.ACL,
				)
			} else {
				results.AddPassed(&bucket)
			}

			for _, object := range bucket.Objects {
				if object.ACL.EqualTo("public-read") {
					results.Add(
						"Object is publicly exposed.",
						object.ACL,
					)
				} else {
					results.AddPassed(&object)
				}
			}
		}
		return
	},
)
