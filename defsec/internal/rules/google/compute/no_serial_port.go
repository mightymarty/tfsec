package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoSerialPort = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0032",
		Provider:    providers2.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-serial-port",
		Summary:     "Disable serial port connectivity for all instances",
		Impact:      "Unrestricted network access to the serial console of the instance",
		Resolution:  "Disable serial port access",
		Explanation: `When serial port access is enabled, the access is not governed by network security rules meaning the port can be exposed publicly.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoSerialPortGoodExamples,
			BadExamples:         terraformNoSerialPortBadExamples,
			Links:               terraformNoSerialPortLinks,
			RemediationMarkdown: terraformNoSerialPortRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.EnableSerialPort.IsTrue() {
				results.Add(
					"Instance has serial port enabled.",
					instance.EnableSerialPort,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
