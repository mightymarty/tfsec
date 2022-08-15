package rules

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	"github.com/mightymarty/tfsec/defsec/pkg/framework"
	"github.com/mightymarty/tfsec/defsec/pkg/scan"
)

func Register(rule scan.Rule, f scan.CheckFunc) rules.RegisteredRule {
	return rules.Register(rule, f)
}

func GetRegistered(fw ...framework.Framework) (registered []rules.RegisteredRule) {
	return rules.GetFrameworkRules(fw...)
}
