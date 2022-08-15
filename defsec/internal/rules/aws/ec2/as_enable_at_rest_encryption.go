package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckASEnableAtRestEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0008",
		Aliases:     []string{"aws-autoscaling-enable-at-rest-encryption"},
		Provider:    providers2.AWSProvider,
		Service:     "ec2",
		ShortCode:   "enable-launch-config-at-rest-encryption",
		Summary:     "Launch configuration with unencrypted block device.",
		Impact:      "The block device could be compromised and read from",
		Resolution:  "Turn on encryption for all block devices",
		Explanation: `Block devices should be encrypted to ensure sensitive data is held securely at rest.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformASEnableAtRestEncryptionGoodExamples,
			BadExamples:         terraformASEnableAtRestEncryptionBadExamples,
			Links:               terraformASEnableAtRestEncryptionLinks,
			RemediationMarkdown: terraformASEnableAtRestEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationASEnableAtRestEncryptionGoodExamples,
			BadExamples:         cloudFormationASEnableAtRestEncryptionBadExamples,
			Links:               cloudFormationASEnableAtRestEncryptionLinks,
			RemediationMarkdown: cloudFormationASEnableAtRestEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, launchConfig := range s.AWS.EC2.LaunchConfigurations {
			if launchConfig.RootBlockDevice != nil && launchConfig.RootBlockDevice.Encrypted.IsFalse() {
				results.Add(
					"Root block device is not encrypted.",
					launchConfig.RootBlockDevice.Encrypted,
				)
			} else {
				results.AddPassed(&launchConfig)
			}
			for _, device := range launchConfig.EBSBlockDevices {
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
