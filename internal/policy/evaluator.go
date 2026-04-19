package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/format"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/aljoshare/oy/internal/scanner"
)

type Violation struct {
	File    string `json:"file"`
	Message string `json:"message"`
}

type Rule struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	File        string `json:"file"`
}

type Evaluator struct {
	modules  map[string]string
	Warnings []string
}

// NewEvaluatorFromDir loads all .rego files from the given directory.
func NewEvaluatorFromDir(dir string) (*Evaluator, error) {
	modules, warnings, err := loadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("no .rego files found in %q", dir)
	}
	return &Evaluator{modules: modules, Warnings: warnings}, nil
}

// NewEvaluatorFromDirs merges .rego files from multiple directories.
// Files from later directories override same-named files from earlier ones.
func NewEvaluatorFromDirs(dirs []string) (*Evaluator, error) {
	modules := map[string]string{}
	var warnings []string
	for _, dir := range dirs {
		m, w, err := loadDir(dir)
		if err != nil {
			return nil, err
		}
		for k, v := range m {
			modules[k] = v
		}
		warnings = append(warnings, w...)
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("no .rego files found in any of the configured repositories")
	}
	return &Evaluator{modules: modules, Warnings: warnings}, nil
}

// NewEvaluatorFromModules creates an evaluator from in-memory modules (for embedded policies).
func NewEvaluatorFromModules(modules map[string]string) *Evaluator {
	return &Evaluator{modules: modules}
}

// filterModule parses src, removes any deny rules that lack a METADATA title,
// and returns the filtered source and a warning for each skipped rule.
func filterModule(filename, src string) (string, []string, error) {
	module, err := ast.ParseModuleWithOpts(filename, src, ast.ParserOptions{ProcessAnnotation: true})
	if err != nil {
		return "", nil, fmt.Errorf("parsing %q: %w", filename, err)
	}

	var kept []*ast.Rule
	var warnings []string
	for _, rule := range module.Rules {
		hasTitle := false
		for _, ann := range rule.Annotations {
			if ann.Title != "" {
				hasTitle = true
				break
			}
		}
		if hasTitle {
			kept = append(kept, rule)
		} else {
			warnings = append(warnings, fmt.Sprintf(
				"warning: rule %q in %q has no METADATA title — skipping",
				rule.Head.Name, filename,
			))
		}
	}

	if len(warnings) == 0 {
		return src, nil, nil
	}

	module.Rules = kept
	filtered, err := format.AstWithOpts(module, format.Opts{RegoVersion: ast.RegoV1})
	if err != nil {
		return "", nil, fmt.Errorf("reprinting filtered module %q: %w", filename, err)
	}
	return string(filtered), warnings, nil
}

func loadDir(dir string) (modules map[string]string, warnings []string, err error) {
	modules = map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("reading policy directory %q: %w", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.EqualFold(filepath.Ext(name), ".rego") || strings.Contains(name, "_test") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("reading policy %q: %w", path, err)
		}
		src, w, err := filterModule(path, string(data))
		if err != nil {
			return nil, nil, err
		}
		warnings = append(warnings, w...)
		// Use full path as key so files from different dirs don't collide.
		modules[path] = src
	}
	return modules, warnings, nil
}

// Rules returns all rules with METADATA annotations across all loaded policy files.
func (e *Evaluator) Rules() ([]Rule, error) {
	var rules []Rule
	for filename, src := range e.modules {
		module, err := ast.ParseModuleWithOpts(filename, src, ast.ParserOptions{ProcessAnnotation: true})
		if err != nil {
			return nil, fmt.Errorf("parsing %q: %w", filename, err)
		}
		for _, rule := range module.Rules {
			for _, ann := range rule.Annotations {
				if ann.Title == "" {
					continue
				}
				rules = append(rules, Rule{
					Title:       ann.Title,
					Description: ann.Description,
					File:        filename,
				})
			}
		}
	}
	return rules, nil
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
