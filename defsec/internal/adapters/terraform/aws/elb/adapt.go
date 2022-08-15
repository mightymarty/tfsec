package elb

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	elb2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/elb"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) elb2.ELB {

	adapter := adapter{
		listenerIDs: modules.GetChildResourceIDMapByType("aws_lb_listener", "aws_alb_listener"),
	}

	return elb2.ELB{
		LoadBalancers: adapter.adaptLoadBalancers(modules),
	}
}

type adapter struct {
	listenerIDs terraform2.ResourceIDResolutions
}

func (a *adapter) adaptLoadBalancers(modules terraform2.Modules) []elb2.LoadBalancer {
	var loadBalancers []elb2.LoadBalancer
	for _, resource := range modules.GetResourcesByType("aws_lb") {
		loadBalancers = append(loadBalancers, a.adaptLoadBalancer(resource, modules))
	}
	for _, resource := range modules.GetResourcesByType("aws_alb") {
		loadBalancers = append(loadBalancers, a.adaptLoadBalancer(resource, modules))
	}
	for _, resource := range modules.GetResourcesByType("aws_elb") {
		loadBalancers = append(loadBalancers, a.adaptClassicLoadBalancer(resource, modules))
	}

	orphanResources := modules.GetResourceByIDs(a.listenerIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := elb2.LoadBalancer{
			Metadata:                types2.NewUnmanagedMetadata(),
			Type:                    types2.StringDefault(elb2.TypeApplication, types2.NewUnmanagedMetadata()),
			DropInvalidHeaderFields: types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
			Internal:                types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
			Listeners:               nil,
		}
		for _, listenerResource := range orphanResources {
			orphanage.Listeners = append(orphanage.Listeners, adaptListener(listenerResource, "application"))
		}
		loadBalancers = append(loadBalancers, orphanage)
	}

	return loadBalancers
}

func (a *adapter) adaptLoadBalancer(resource *terraform2.Block, module terraform2.Modules) elb2.LoadBalancer {
	var listeners []elb2.Listener

	typeAttr := resource.GetAttribute("load_balancer_type")
	typeVal := typeAttr.AsStringValueOrDefault("application", resource)

	dropInvalidHeadersAttr := resource.GetAttribute("drop_invalid_header_fields")
	dropInvalidHeadersVal := dropInvalidHeadersAttr.AsBoolValueOrDefault(false, resource)

	internalAttr := resource.GetAttribute("internal")
	internalVal := internalAttr.AsBoolValueOrDefault(false, resource)

	listenerBlocks := module.GetReferencingResources(resource, "aws_lb_listener", "load_balancer_arn")
	listenerBlocks = append(listenerBlocks, module.GetReferencingResources(resource, "aws_alb_listener", "load_balancer_arn")...)

	for _, listenerBlock := range listenerBlocks {
		a.listenerIDs.Resolve(listenerBlock.ID())
		listeners = append(listeners, adaptListener(listenerBlock, typeVal.Value()))
	}
	return elb2.LoadBalancer{
		Metadata:                resource.GetMetadata(),
		Type:                    typeVal,
		DropInvalidHeaderFields: dropInvalidHeadersVal,
		Internal:                internalVal,
		Listeners:               listeners,
	}
}

func (a *adapter) adaptClassicLoadBalancer(resource *terraform2.Block, module terraform2.Modules) elb2.LoadBalancer {
	internalAttr := resource.GetAttribute("internal")
	internalVal := internalAttr.AsBoolValueOrDefault(false, resource)

	return elb2.LoadBalancer{
		Metadata:                resource.GetMetadata(),
		Type:                    types2.String("classic", resource.GetMetadata()),
		DropInvalidHeaderFields: types2.BoolDefault(false, resource.GetMetadata()),
		Internal:                internalVal,
		Listeners:               nil,
	}
}

func adaptListener(listenerBlock *terraform2.Block, typeVal string) elb2.Listener {
	listener := elb2.Listener{
		Metadata:       listenerBlock.GetMetadata(),
		Protocol:       types2.StringDefault("", listenerBlock.GetMetadata()),
		TLSPolicy:      types2.StringDefault("", listenerBlock.GetMetadata()),
		DefaultActions: nil,
	}

	protocolAttr := listenerBlock.GetAttribute("protocol")
	if typeVal == "application" {
		listener.Protocol = protocolAttr.AsStringValueOrDefault("HTTP", listenerBlock)
	}

	sslPolicyAttr := listenerBlock.GetAttribute("ssl_policy")
	listener.TLSPolicy = sslPolicyAttr.AsStringValueOrDefault("", listenerBlock)

	for _, defaultActionBlock := range listenerBlock.GetBlocks("default_action") {
		action := elb2.Action{
			Metadata: defaultActionBlock.GetMetadata(),
			Type:     defaultActionBlock.GetAttribute("type").AsStringValueOrDefault("", defaultActionBlock),
		}
		listener.DefaultActions = append(listener.DefaultActions, action)
	}

	return listener
}
