package emr

import (
	"encoding/json"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableLocalDiskEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0139",
		Provider:    providers2.AWSProvider,
		Service:     "emr",
		ShortCode:   "enable-local-disk-encryption",
		Summary:     "Enable local-disk encryption for EMR clusters.",
		Impact:      "Local-disk data in the EMR cluster could be compromised if accessed.",
		Resolution:  "Enable local-disk encryption for EMR cluster",
		Explanation: `Data stored within an EMR instances should be encrypted to ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist_800-171.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableLocalDiskEncryptionGoodExamples,
			BadExamples:         terraformEnableLocalDiskEncryptionBadExamples,
			Links:               terraformEnableLocalDiskEncryptionLinks,
			RemediationMarkdown: terraformEnableLocalDiskEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, conf := range s.AWS.EMR.SecurityConfiguration {
			vars, err := readVarsFromConfigurationLocalDisk(conf.Configuration.Value())
			if err != nil {
				continue
			}

			if vars.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType == "" {
				results.Add(
					"EMR cluster does not have local-disk encryption enabled.",
					conf.Configuration,
				)
			} else {
				results.AddPassed(&conf)
			}

		}
		return
	},
)

func readVarsFromConfigurationLocalDisk(raw string) (*conf, error) {
	var testConf conf
	if err := json.Unmarshal([]byte(raw), &testConf); err != nil {
		return nil, err
	}

	return &testConf, nil
}
