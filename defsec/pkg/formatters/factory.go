package formatters

import (
	"io"

	"github.com/mightymarty/tfsec/defsec/pkg/scan"
)

func New() *factory {
	return &factory{
		base: NewBase(),
	}
}

func NewReturned() *factoryReturned {
	return &factoryReturned{
		base: NewBaseReturned(),
	}
}

type factory struct {
	base *Base
}

type factoryReturned struct {
	base *BaseReturned
}

func (f *factory) Build() Formatter {
	return f.base
}

func (f *factory) WithIncludePassed(include bool) *factory {
	f.base.includePassed = include
	return f
}

func (f *factory) WithIncludeIgnored(include bool) *factory {
	f.base.includeIgnored = include
	return f
}

func (f *factory) WithMetricsEnabled(enabled bool) *factory {
	f.base.enableMetrics = enabled
	return f
}

func (f *factory) WithDebugEnabled(enabled bool) *factory {
	f.base.enableDebug = enabled
	return f
}

func (f *factory) WithColoursEnabled(enabled bool) *factory {
	f.base.enableColours = enabled
	return f
}

func (f *factory) WithGroupingEnabled(enabled bool) *factory {
	f.base.enableGrouping = enabled
	return f
}

func (f *factory) WithFSRoot(root string) *factory {
	f.base.fsRoot = root
	return f
}

func (f *factory) WithRelativePaths(relative bool) *factory {
	f.base.relative = relative
	return f
}

func (f *factory) WithBaseDir(dir string) *factory {
	f.base.baseDir = dir
	return f
}

func (f *factory) WithCustomFormatterFunc(fn func(ConfigurableFormatter, scan.Results) error) *factory {
	f.base.outputOverride = fn
	return f
}

func (f *factory) WithLinksFunc(fn func(result scan.Result) []string) *factory {
	f.base.linksOverride = fn
	return f
}

func (f *factory) WithWriter(w io.Writer) *factory {
	f.base.writer = w
	return f
}

func (f *factoryReturned) BuildReturned() FormatterReturned {
	return f.base
}

func (f *factoryReturned) WithIncludePassedReturned(include bool) *factoryReturned {
	f.base.includePassed = include
	return f
}

func (f *factoryReturned) WithIncludeIgnoredReturned(include bool) *factoryReturned {
	f.base.includeIgnored = include
	return f
}

func (f *factoryReturned) WithMetricsEnabledReturned(enabled bool) *factoryReturned {
	f.base.enableMetrics = enabled
	return f
}

func (f *factoryReturned) WithDebugEnabledReturned(enabled bool) *factoryReturned {
	f.base.enableDebug = enabled
	return f
}

func (f *factoryReturned) WithColoursEnabledReturned(enabled bool) *factoryReturned {
	f.base.enableColours = enabled
	return f
}

func (f *factoryReturned) WithGroupingEnabledReturned(enabled bool) *factoryReturned {
	f.base.enableGrouping = enabled
	return f
}

func (f *factoryReturned) WithFSRoot(root string) *factoryReturned {
	f.base.fsRoot = root
	return f
}

func (f *factoryReturned) WithRelativePaths(relative bool) *factoryReturned {
	f.base.relative = relative
	return f
}

func (f *factoryReturned) WithBaseDir(dir string) *factoryReturned {
	f.base.baseDir = dir
	return f
}

func (f *factoryReturned) WithCustomFormatterFuncReturned(fn func(ConfigurableFormatter, scan.Results) ([]byte, error)) *factoryReturned {
	f.base.outputOverride = fn
	return f
}

func (f *factoryReturned) WithLinksFuncReturned(fn func(result scan.Result) []string) *factoryReturned {
	f.base.linksOverride = fn
	return f
}

func (f *factoryReturned) WithWriterReturned(w io.Writer) *factoryReturned {
	f.base.writer = w
	return f
}

func (f *factory) AsJSON() *factory {
	f.base.outputOverride = outputJSON
	return f
}

func (f *factory) AsCheckStyle() *factory {
	f.base.outputOverride = outputCheckStyle
	return f
}

func (f *factory) AsCSV() *factory {
	f.base.outputOverride = outputCSV
	return f
}

func (f *factory) AsJUnit() *factory {
	f.base.outputOverride = outputJUnit
	return f
}

func (f *factory) AsSARIF() *factory {
	f.base.outputOverride = outputSARIF
	return f
}

func (f *factoryReturned) AsJSONReturned() *factoryReturned {
	f.base.outputOverride = outputJSONReturned
	return f
}

func (f *factoryReturned) AsCheckStyleReturned() *factoryReturned {
	f.base.outputOverride = outputCheckStyleReturned
	return f
}
