package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/aljoshare/oy/internal/scanner"
)

type Violation struct {
	File    string `json:"file"`
	Message string `json:"message"`
}

type Evaluator struct {
	modules map[string]string
}

// NewEvaluatorFromDir loads all .rego files from the given directory.
func NewEvaluatorFromDir(dir string) (*Evaluator, error) {
	modules, err := loadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("no .rego files found in %q", dir)
	}
	return &Evaluator{modules: modules}, nil
}

// NewEvaluatorFromDirs merges .rego files from multiple directories.
// Files from later directories override same-named files from earlier ones.
func NewEvaluatorFromDirs(dirs []string) (*Evaluator, error) {
	modules := map[string]string{}
	for _, dir := range dirs {
		m, err := loadDir(dir)
		if err != nil {
			return nil, err
		}
		for k, v := range m {
			modules[k] = v
		}
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("no .rego files found in any of the configured repositories")
	}
	return &Evaluator{modules: modules}, nil
}

func loadDir(dir string) (map[string]string, error) {
	modules := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading policy directory %q: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".rego") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading policy %q: %w", path, err)
		}
		// Use full path as key so files from different dirs don't collide.
		modules[path] = string(data)
	}
	return modules, nil
}

// NewEvaluatorFromModules creates an evaluator from in-memory modules (for embedded policies).
func NewEvaluatorFromModules(modules map[string]string) *Evaluator {
	return &Evaluator{modules: modules}
}

// Evaluate runs all policies against the given file and returns any violations.
func (e *Evaluator) Evaluate(ctx context.Context, f *scanner.File) ([]Violation, error) {
	input := map[string]interface{}{
		"path":    f.Path,
		"content": f.Content,
		"lines":   f.Lines,
	}

	opts := []func(*rego.Rego){
		rego.Query("data.oy.deny"),
		rego.Input(input),
	}
	for name, src := range e.modules {
		opts = append(opts, rego.Module(name, src))
	}

	r := rego.New(opts...)
	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluating policy for %q: %w", f.Path, err)
	}

	var violations []Violation
	for _, result := range rs {
		for _, expr := range result.Expressions {
			switch v := expr.Value.(type) {
			case []interface{}:
				for _, item := range v {
					if msg, ok := item.(string); ok {
						violations = append(violations, Violation{File: f.Path, Message: msg})
					}
				}
			case map[string]interface{}:
				for msg := range v {
					violations = append(violations, Violation{File: f.Path, Message: msg})
				}
			}
		}
	}
	return violations, nil
}
