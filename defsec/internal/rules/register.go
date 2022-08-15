package rules

import (
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
	"sync"
)

type RegisteredRule struct {
	number    int
	rule      scan2.Rule
	checkFunc scan2.CheckFunc
}

func (r RegisteredRule) HasLogic() bool {
	return r.checkFunc != nil
}

func (r RegisteredRule) Evaluate(s *state2.State) scan2.Results {
	if r.checkFunc == nil {
		return nil
	}
	results := r.checkFunc(s)
	for i := range results {
		results[i].SetRule(r.rule)
	}
	return results
}

func (r RegisteredRule) Rule() scan2.Rule {
	return r.rule
}

func (r *RegisteredRule) AddLink(link string) {
	r.rule.Links = append([]string{link}, r.rule.Links...)
}

type registry struct {
	sync.RWMutex
	index      int
	frameworks map[framework2.Framework][]RegisteredRule
}

var coreRegistry = registry{
	frameworks: make(map[framework2.Framework][]RegisteredRule),
}

func Reset() {
	coreRegistry.Reset()
}

func Register(rule scan2.Rule, f scan2.CheckFunc) RegisteredRule {
	return coreRegistry.register(rule, f)
}

func Deregister(rule RegisteredRule) {
	coreRegistry.deregister(rule)
}

func (r *registry) register(rule scan2.Rule, f scan2.CheckFunc) RegisteredRule {
	r.Lock()
	defer r.Unlock()
	if len(rule.Frameworks) == 0 {
		rule.Frameworks = map[framework2.Framework][]string{framework2.Default: nil}
	}
	registeredRule := RegisteredRule{
		number:    r.index,
		rule:      rule,
		checkFunc: f,
	}
	r.index++
	for fw := range rule.Frameworks {
		r.frameworks[fw] = append(r.frameworks[fw], registeredRule)
	}
	return registeredRule
}

func (r *registry) deregister(rule RegisteredRule) {
	r.Lock()
	defer r.Unlock()
	for fw := range r.frameworks {
		for i, registered := range r.frameworks[fw] {
			if registered.number == rule.number {
				r.frameworks[fw] = append(r.frameworks[fw][:i], r.frameworks[fw][i+1:]...)
				break
			}
		}
	}
}

func (r *registry) getFrameworkRules(fw ...framework2.Framework) []RegisteredRule {
	r.RLock()
	defer r.RUnlock()
	var registered []RegisteredRule
	if len(fw) == 0 {
		fw = []framework2.Framework{framework2.Default}
	}
	unique := make(map[int]struct{})
	for _, f := range fw {
		for _, rule := range r.frameworks[f] {
			if _, ok := unique[rule.number]; ok {
				continue
			}
			registered = append(registered, rule)
			unique[rule.number] = struct{}{}
		}
	}
	return registered
}

func (r *registry) Reset() {
	r.Lock()
	defer r.Unlock()
	r.frameworks = make(map[framework2.Framework][]RegisteredRule)
}

func GetFrameworkRules(fw ...framework2.Framework) []RegisteredRule {
	return coreRegistry.getFrameworkRules(fw...)
}
