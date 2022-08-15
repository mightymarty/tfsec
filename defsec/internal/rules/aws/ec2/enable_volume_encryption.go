package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableVolumeEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0026",
		Aliases:     []string{"aws-ebs-enable-volume-encryption"},
		Provider:    providers2.AWSProvider,
		Service:     "ec2",
		ShortCode:   "enable-volume-encryption",
		Summary:     "EBS volumes must be encrypted",
		Impact:      "Unencrypted sensitive data is vulnerable to compromise.",
		Resolution:  "Enable encryption of EBS volumes",
		Explanation: `By enabling encryption on EBS volumes you protect the volume, the disk I/O and any derived snapshots from compromise if intercepted.`,
		Links:       []string{"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableVolumeEncryptionGoodExamples,
			BadExamples:         terraformEnableVolumeEncryptionBadExamples,
			Links:               terraformEnableVolumeEncryptionLinks,
			RemediationMarkdown: terraformEnableVolumeEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableVolumeEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableVolumeEncryptionBadExamples,
			Links:               cloudFormationEnableVolumeEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableVolumeEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, volume := range s.AWS.EC2.Volumes {
			if volume.IsUnmanaged() {
				continue
			}
			if volume.Encryption.Enabled.IsFalse() {
				results.Add(
					"EBS volume is not encrypted.",
					volume.Encryption.Enabled,
				)
			} else {
				results.AddPassed(&volume)
			}
		}
		return
	},
)
