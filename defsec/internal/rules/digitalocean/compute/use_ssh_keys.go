package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckUseSshKeys = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-DIG-0004",
		Provider:    providers2.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "use-ssh-keys",
		Summary:     "SSH Keys are the preferred way to connect to your droplet, no keys are supplied",
		Impact:      "Logging in with username and password is easier to compromise",
		Resolution:  "Use ssh keys for login",
		Explanation: `When working with a server, you’ll likely spend most of your time in a terminal session connected to your server through SSH. A more secure alternative to password-based logins, SSH keys use encryption to provide a secure way of logging into your server and are recommended for all users.`,
		Links: []string{
			"https://www.digitalocean.com/community/tutorials/understanding-the-ssh-encryption-and-connection-process",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformUseSshKeysGoodExamples,
			BadExamples:         terraformUseSshKeysBadExamples,
			Links:               terraformUseSshKeysLinks,
			RemediationMarkdown: terraformUseSshKeysRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, droplet := range s.DigitalOcean.Compute.Droplets {
			if droplet.IsUnmanaged() {
				continue
			}
			if len(droplet.SSHKeys) == 0 {
				results.Add(
					"Droplet does not have an SSH key specified.",
					&droplet,
				)
			} else {
				results.AddPassed(&droplet)
			}
		}
		return
	},
)
