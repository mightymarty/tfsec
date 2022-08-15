package compute

import (
	compute2 "github.com/mightymarty/tfsec/defsec/pkg/providers/digitalocean/compute"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) compute2.Compute {
	return compute2.Compute{
		Droplets:           adaptDroplets(modules),
		Firewalls:          adaptFirewalls(modules),
		LoadBalancers:      adaptLoadBalancers(modules),
		KubernetesClusters: adaptKubernetesClusters(modules),
	}
}

func adaptDroplets(module terraform2.Modules) []compute2.Droplet {
	var droplets []compute2.Droplet

	for _, module := range module {
		for _, block := range module.GetResourcesByType("digitalocean_droplet") {
			droplet := compute2.Droplet{
				Metadata: block.GetMetadata(),
				SSHKeys:  nil,
			}
			sshKeys := block.GetAttribute("ssh_keys")
			if sshKeys != nil {
				droplet.SSHKeys = sshKeys.AsStringValues()
			}

			droplets = append(droplets, droplet)
		}
	}
	return droplets
}

func adaptFirewalls(module terraform2.Modules) []compute2.Firewall {
	var firewalls []compute2.Firewall

	for _, block := range module.GetResourcesByType("digitalocean_firewall") {
		inboundRules := block.GetBlocks("inbound_rule")
		outboundRules := block.GetBlocks("outbound_rule")

		inboundFirewallRules := []compute2.InboundFirewallRule{}
		for _, inBoundRule := range inboundRules {
			inboundFirewallRule := compute2.InboundFirewallRule{
				Metadata: inBoundRule.GetMetadata(),
			}
			if ibSourceAddresses := inBoundRule.GetAttribute("source_addresses"); ibSourceAddresses != nil {
				inboundFirewallRule.SourceAddresses = ibSourceAddresses.AsStringValues()
			}
			inboundFirewallRules = append(inboundFirewallRules, inboundFirewallRule)
		}

		outboundFirewallRules := []compute2.OutboundFirewallRule{}
		for _, outBoundRule := range outboundRules {
			outboundFirewallRule := compute2.OutboundFirewallRule{
				Metadata: outBoundRule.GetMetadata(),
			}
			if obDestinationAddresses := outBoundRule.GetAttribute("destination_addresses"); obDestinationAddresses != nil {
				outboundFirewallRule.DestinationAddresses = obDestinationAddresses.AsStringValues()
			}
			outboundFirewallRules = append(outboundFirewallRules, outboundFirewallRule)
		}
		firewalls = append(firewalls, compute2.Firewall{
			Metadata:      block.GetMetadata(),
			InboundRules:  inboundFirewallRules,
			OutboundRules: outboundFirewallRules,
		})
	}

	return firewalls
}

func adaptLoadBalancers(module terraform2.Modules) (loadBalancers []compute2.LoadBalancer) {

	for _, block := range module.GetResourcesByType("digitalocean_loadbalancer") {
		forwardingRules := block.GetBlocks("forwarding_rule")
		fRules := []compute2.ForwardingRule{}

		for _, fRule := range forwardingRules {
			rule := compute2.ForwardingRule{}
			rule.Metadata = fRule.GetMetadata()
			rule.EntryProtocol = fRule.GetAttribute("entry_protocol").AsStringValueOrDefault("", fRule)
			fRules = append(fRules, rule)
		}
		loadBalancers = append(loadBalancers, compute2.LoadBalancer{
			Metadata:        block.GetMetadata(),
			ForwardingRules: fRules,
		})
	}

	return loadBalancers
}

func adaptKubernetesClusters(module terraform2.Modules) (kubernetesClusters []compute2.KubernetesCluster) {
	for _, block := range module.GetResourcesByType("digitalocean_kubernetes_cluster") {
		kubernetesClusters = append(kubernetesClusters, compute2.KubernetesCluster{
			Metadata:     block.GetMetadata(),
			AutoUpgrade:  block.GetAttribute("auto_upgrade").AsBoolValueOrDefault(false, block),
			SurgeUpgrade: block.GetAttribute("surge_upgrade").AsBoolValueOrDefault(false, block),
		})
	}
	return kubernetesClusters
}
