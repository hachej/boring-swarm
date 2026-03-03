package dsl

import "path/filepath"

func ResolvePromptPath(projectRoot, promptRel string) string {
	return filepath.Join(projectRoot, ".bsw", filepath.Clean(promptRel))
}
