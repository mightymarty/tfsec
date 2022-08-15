package formatters

import (
	"encoding/json"

	"github.com/mightymarty/tfsec/defsec/pkg/scan"
)

func outputJSON(b ConfigurableFormatter, results scan.Results) error {
	jsonWriter := json.NewEncoder(b.Writer())
	jsonWriter.SetIndent("", "\t")
	var flatResults []scan.FlatResult
	for _, result := range results {
		switch result.Status() {
		case scan.StatusIgnored:
			if !b.IncludeIgnored() {
				continue
			}
		case scan.StatusPassed:
			if !b.IncludePassed() {
				continue
			}
		}
		flat := result.Flatten()
		flat.Links = b.GetLinks(result)
		flat.Location.Filename = b.Path(result)
		flatResults = append(flatResults, flat)
	}
	return jsonWriter.Encode(struct {
		Results []scan.FlatResult `json:"results"`
	}{flatResults})
}

func outputJSONReturned(b ConfigurableFormatter, results scan.Results) ([]byte, error) {
	var flatResults []scan.FlatResult
	for _, result := range results {
		switch result.Status() {
		case scan.StatusIgnored:
			if !b.IncludeIgnored() {
				continue
			}
		case scan.StatusPassed:
			if !b.IncludePassed() {
				continue
			}
		}
		flat := result.Flatten()
		flat.Links = b.GetLinks(result)
		flat.Location.Filename = b.Path(result)
		flatResults = append(flatResults, flat)
	}

	returnResults, err := json.MarshalIndent(flatResults, "results", "\t")

	return returnResults, err
}
