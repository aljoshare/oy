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

func FindMarkdownFiles(root string) ([]*File, error) {
	var files []*File

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".md") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		files = append(files, &File{
			Path:    path,
			Content: content,
			Lines:   strings.Split(content, "\n"),
		})
		return nil
	})
	return files, err
}
