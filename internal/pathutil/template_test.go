package pathutil

import "testing"

func TestFillPathTemplate(t *testing.T) {
	got := FillPathTemplate("/items/{id}/sub/{other}")
	want := "/items/axiom-id-ph/sub/axiom-other-ph"
	if got != want {
		t.Fatalf("%q", got)
	}
}
