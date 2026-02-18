package engine

import (
	"fmt"
	"sync"
)

// Framework is the interface every compliance framework must implement.
type Framework interface {
	ID() string
	Name() string
	Checks() []Check
}

// Registry manages registered compliance frameworks.
type Registry struct {
	mu         sync.RWMutex
	frameworks map[string]Framework
	order      []string
}

// NewRegistry creates an empty framework registry.
func NewRegistry() *Registry {
	return &Registry{
		frameworks: make(map[string]Framework),
	}
}

// Register adds a framework to the registry.
func (r *Registry) Register(f Framework) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.frameworks[f.ID()]; exists {
		return fmt.Errorf("framework %q already registered", f.ID())
	}
	r.frameworks[f.ID()] = f
	r.order = append(r.order, f.ID())
	return nil
}

// Get returns a framework by ID.
func (r *Registry) Get(id string) (Framework, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.frameworks[id]
	return f, ok
}

// All returns all registered frameworks in registration order.
func (r *Registry) All() []Framework {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Framework, 0, len(r.order))
	for _, id := range r.order {
		result = append(result, r.frameworks[id])
	}
	return result
}

// IDs returns the IDs of all registered frameworks.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string(nil), r.order...)
}

// Filter returns a new registry containing only the specified frameworks.
func (r *Registry) Filter(ids []string) *Registry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	filtered := NewRegistry()
	allowed := make(map[string]bool, len(ids))
	for _, id := range ids {
		allowed[id] = true
	}
	for _, id := range r.order {
		if allowed[id] {
			filtered.frameworks[id] = r.frameworks[id]
			filtered.order = append(filtered.order, id)
		}
	}
	return filtered
}
