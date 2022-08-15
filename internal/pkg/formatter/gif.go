package formatter

import (
	"github.com/mightymarty/tfsec/defsec/pkg/scan"
	scanner "github.com/mightymarty/tfsec/defsec/pkg/scanners/terraform"

	"github.com/liamg/gifwrap/pkg/ascii"
	"github.com/mightymarty/tfsec/defsec/pkg/formatters"
)

func GifWithMetrics(metrics scanner.Metrics, theme string, withColours bool) func(b formatters.ConfigurableFormatter, results scan.Results) error {
	return func(b formatters.ConfigurableFormatter, results scan.Results) error {

		failCount := len(results.GetFailed())

		gifSrc := "https://media.giphy.com/media/kyLYXonQYYfwYDIeZl/source.gif"

		if failCount > 0 {
			gifSrc = "https://i.giphy.com/media/A1SxC5HRrD3MY/source.gif"
		}

		if renderer, err := ascii.FromURL(gifSrc); err == nil {
			renderer.SetFill(true)
			_ = renderer.PlayOnce()
		}

		return DefaultWithMetrics(metrics, false, theme, withColours, false)(b, results)
	}
}
