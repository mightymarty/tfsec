package sam

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/iam"
)

type StateMachine struct {
	types.Metadata
	Name                 types.StringValue
	LoggingConfiguration LoggingConfiguration
	ManagedPolicies      []types.StringValue
	Policies             []iam.Policy
	Tracing              TracingConfiguration
}

type LoggingConfiguration struct {
	types.Metadata
	LoggingEnabled types.BoolValue
}

type TracingConfiguration struct {
	types.Metadata
	Enabled types.BoolValue
}
