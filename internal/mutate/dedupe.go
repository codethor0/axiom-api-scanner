package mutate

import "fmt"

// DedupeKey returns a stable key for mutation work items (resume and execution dedup).
func DedupeKey(c Candidate) string {
	return fmt.Sprintf("%s\x1f%s\x1f%d\x1f%s\x1f%s",
		c.EndpointID, c.RuleID, c.MutationIndex, string(c.Kind), c.Detail)
}
