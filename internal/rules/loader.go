package rules

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Loader reads rule YAML files from a directory tree.
type Loader struct{}

// LoadDir walks root recursively and loads every file ending in .yml or .yaml.
// Each document is validated before being returned.
func (Loader) LoadDir(root string) ([]Rule, error) {
	var collected []Rule
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		rules, err := ParseDocuments(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		collected = append(collected, rules...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return collected, nil
}

// ParseDocuments decodes one or more YAML documents and validates each rule.
func ParseDocuments(data []byte) ([]Rule, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var out []Rule
	for {
		var r Rule
		err := dec.Decode(&r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if r.ID == "" && r.Name == "" {
			continue
		}
		if err := Validate(r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
