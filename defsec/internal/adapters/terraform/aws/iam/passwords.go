package iam

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	iam2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/iam"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
	"math"
)

func adaptPasswordPolicy(modules terraform2.Modules) iam2.PasswordPolicy {

	policy := iam2.PasswordPolicy{
		Metadata:             types2.NewUnmanagedMetadata(),
		ReusePreventionCount: types2.IntDefault(0, types2.NewUnmanagedMetadata()),
		RequireLowercase:     types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
		RequireUppercase:     types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
		RequireNumbers:       types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
		RequireSymbols:       types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
		MaxAgeDays:           types2.IntDefault(math.MaxInt, types2.NewUnmanagedMetadata()),
		MinimumLength:        types2.IntDefault(0, types2.NewUnmanagedMetadata()),
	}

	passwordPolicies := modules.GetResourcesByType("aws_iam_account_password_policy")
	if len(passwordPolicies) == 0 {
		return policy
	}

	// aws only allows a single password policy resource
	policyBlock := passwordPolicies[0]

	policy.Metadata = policyBlock.GetMetadata()

	if attr := policyBlock.GetAttribute("require_lowercase_characters"); attr.IsNotNil() {
		policy.RequireLowercase = types2.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireLowercase = types2.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_uppercase_characters"); attr.IsNotNil() {
		policy.RequireUppercase = types2.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireUppercase = types2.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_numbers"); attr.IsNotNil() {
		policy.RequireNumbers = types2.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireNumbers = types2.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_symbols"); attr.IsNotNil() {
		policy.RequireSymbols = types2.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireSymbols = types2.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("password_reuse_prevention"); attr.IsNumber() {
		value := attr.AsNumber()
		policy.ReusePreventionCount = types2.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.ReusePreventionCount = types2.IntDefault(0, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("max_password_age"); attr.IsNumber() {
		value := attr.AsNumber()
		policy.MaxAgeDays = types2.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.MaxAgeDays = types2.IntDefault(math.MaxInt, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("minimum_password_length"); attr.IsNumber() {
		value := attr.AsNumber()
		policy.MinimumLength = types2.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.MinimumLength = types2.IntDefault(0, policyBlock.GetMetadata())
	}

	return policy
}
