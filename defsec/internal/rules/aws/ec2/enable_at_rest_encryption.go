package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0131",
		Provider:    providers2.AWSProvider,
		Service:     "ec2",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "Instance with unencrypted block device.",
		Impact:      "The block device could be compromised and read from",
		Resolution:  "Turn on encryption for all block devices",
		Explanation: `Block devices should be encrypted to ensure sensitive data is held securely at rest.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableAtRestEncryptionGoodExamples,
			BadExamples:         terraformEnableAtRestEncryptionBadExamples,
			Links:               terraformEnableAtRestEncryptionLinks,
			RemediationMarkdown: terraformEnableAtRestEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableAtRestEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableAtRestEncryptionBadExamples,
			Links:               cloudFormationEnableAtRestEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableAtRestEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.AWS.EC2.Instances {
			if instance.RootBlockDevice != nil && instance.RootBlockDevice.Encrypted.IsFalse() {
				results.Add(
					"Root block device is not encrypted.",
					instance.RootBlockDevice.Encrypted,
				)
			} else {
				results.AddPassed(&instance)
			}
			for _, device := range instance.EBSBlockDevices {
				if device.Encrypted.IsFalse() {
					results.Add(
						"EBS block device is not encrypted.",
						device.Encrypted,
					)
				} else {
					results.AddPassed(device)
				}
			}
		}
		return
	},
)
