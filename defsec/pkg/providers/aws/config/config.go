package config

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type Config struct {
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	types.Metadata
	SourceAllRegions types.BoolValue
	IsDefined        bool
}
