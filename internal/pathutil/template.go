package pathutil

import "regexp"

var tplSeg = regexp.MustCompile(`\{[^}]+\}`)

// PlaceholderForParam is the filled segment for a template parameter name (matches FillPathTemplate).
func PlaceholderForParam(param string) string {
	return "axiom-" + param + "-ph"
}

// FillPathTemplate replaces each `{param}` segment with a deterministic placeholder.
func FillPathTemplate(pathTemplate string) string {
	return tplSeg.ReplaceAllStringFunc(pathTemplate, func(seg string) string {
		inner := seg[1 : len(seg)-1]
		return PlaceholderForParam(inner)
	})
}
