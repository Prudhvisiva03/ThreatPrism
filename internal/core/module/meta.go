package module

import (
	"fmt"
	"sort"

	"github.com/threatprism/threatprism/pkg/models"
)

// topoSort orders modules so dependencies precede dependents (Kahn's
// algorithm). Ties are broken by slug for deterministic output. Edges to
// modules outside the set are ignored.
func topoSort(set map[string]Module) ([]Module, error) {
	indeg := make(map[string]int, len(set))
	adj := make(map[string][]string, len(set))
	for slug := range set {
		indeg[slug] = 0
	}
	for slug, m := range set {
		for _, dep := range m.Requires() {
			if _, ok := set[dep]; !ok {
				continue // dependency not in the selected set
			}
			adj[dep] = append(adj[dep], slug)
			indeg[slug]++
		}
	}

	// Seed the queue with zero-indegree nodes, sorted for determinism.
	var queue []string
	for slug, d := range indeg {
		if d == 0 {
			queue = append(queue, slug)
		}
	}
	sort.Strings(queue)

	var order []Module
	for len(queue) > 0 {
		slug := queue[0]
		queue = queue[1:]
		order = append(order, set[slug])

		next := append([]string(nil), adj[slug]...)
		sort.Strings(next)
		for _, n := range next {
			indeg[n]--
			if indeg[n] == 0 {
				queue = append(queue, n)
				sort.Strings(queue)
			}
		}
	}

	if len(order) != len(set) {
		return nil, fmt.Errorf("module: dependency cycle detected among %d modules", len(set))
	}
	return order, nil
}

// Meta is an embeddable struct that supplies the boilerplate Module metadata
// methods, so a concrete module only has to implement Run.
//
//	type MyModule struct{ module.Meta }
//	func New() *MyModule {
//	    return &MyModule{Meta: module.Meta{
//	        ModSlug: "mymod", ModName: "My Module", ...,
//	    }}
//	}
//	func (m *MyModule) Run(rc *module.RunContext) error { ... }
type Meta struct {
	ModSlug     string
	ModName     string
	ModDesc     string
	ModCategory string
	ModModes    []models.Mode
	ModRequires []string
}

func (m Meta) Slug() string          { return m.ModSlug }
func (m Meta) Name() string          { return m.ModName }
func (m Meta) Description() string   { return m.ModDesc }
func (m Meta) Category() string      { return m.ModCategory }
func (m Meta) Modes() []models.Mode  { return m.ModModes }
func (m Meta) Requires() []string    { return m.ModRequires }
