package defaults

import (
	"embed"
	"io/fs"
	"sort"
	"strings"
)

//go:embed prompts/*.md flows/*.yml
var embedded embed.FS

func Read(path string) ([]byte, error) {
	return embedded.ReadFile(strings.TrimSpace(path))
}

func Files() ([]string, error) {
	out := []string{}
	if err := fs.WalkDir(embedded, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasPrefix(path, "prompts/") || strings.HasPrefix(path, "flows/") {
			out = append(out, path)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}
