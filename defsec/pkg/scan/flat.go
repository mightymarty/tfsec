package scan

import (
	"github.com/mightymarty/tfsec/defsec/pkg/providers"
	"github.com/mightymarty/tfsec/defsec/pkg/severity"
)

type FlatResult struct {
	RuleID          string             `json:"rule_id"`
	LongID          string             `json:"long_id"`
	RuleSummary     string             `json:"rule_description"`
	RuleProvider    providers.Provider `json:"rule_provider"`
	RuleService     string             `json:"rule_service"`
	Impact          string             `json:"impact"`
	Resolution      string             `json:"resolution"`
	Links           []string           `json:"links"`
	Description     string             `json:"description"`
	RangeAnnotation string             `json:"-"`
	Severity        severity.Severity  `json:"severity"`
	Warning         bool               `json:"warning"`
	Status          Status             `json:"status"`
	Resource        string             `json:"resource"`
	Location        FlatRange          `json:"location"`
}

type FlatRange struct {
	Filename  string `json:"filename"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

func (r Results) Flatten() []FlatResult {
	var results []FlatResult
	for _, original := range r {
		results = append(results, original.Flatten())
	}
	return results
}

func (r *Result) Flatten() FlatResult {
	rng := r.metadata.Range()

	resMetadata := r.metadata

	for resMetadata.Parent() != nil {
		resMetadata = *resMetadata.Parent()
	}

	resource := ""
	if resMetadata.Reference() != nil {
		resource = resMetadata.Reference().LogicalID()
	}

	return FlatResult{
		RuleID:          r.rule.AVDID,
		LongID:          r.Rule().LongID(),
		RuleSummary:     r.rule.Summary,
		RuleProvider:    r.rule.Provider,
		RuleService:     r.rule.Service,
		Impact:          r.rule.Impact,
		Resolution:      r.rule.Resolution,
		Links:           r.rule.Links,
		Description:     r.Description(),
		RangeAnnotation: r.Annotation(),
		Severity:        r.rule.Severity,
		Status:          r.status,
		Resource:        resource,
		Warning:         r.IsWarning(),
		Location: FlatRange{
			Filename:  rng.GetFilename(),
			StartLine: rng.GetStartLine(),
			EndLine:   rng.GetEndLine(),
		},
	}
}
