package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

type File struct {
	Path    string
	Content string
	Lines   []string
}

// FindMarkdownFiles walks root for *.md files, honouring a .oyignore file in
// the root directory (or its parent when root is a file). It returns the files
// to scan and the number of files that were skipped due to ignore rules.
func FindMarkdownFiles(root string) (files []*File, ignored int, err error) {
	ignoreRoot := root
	if info, e := os.Stat(root); e == nil && !info.IsDir() {
		ignoreRoot = filepath.Dir(root)
	}

	patterns, err := loadIgnorePatterns(ignoreRoot)
	if err != nil {
		return nil, 0, err
	}

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".md") {
			return nil
		}
		if matchesAny(path, ignoreRoot, patterns) {
			ignored++
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		content := string(data)
		files = append(files, &File{
			Path:    path,
			Content: content,
			Lines:   strings.Split(content, "\n"),
		})
		return nil
	})
	return files, ignored, err
}

func loadIgnorePatterns(dir string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(dir, ".oyignore"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var patterns []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, nil
}

func matchesAny(path, root string, patterns []string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, rel); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, filepath.Base(rel)); matched {
			return true
		}
	}
	return false
}
