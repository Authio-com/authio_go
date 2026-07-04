package platformsecrets

import "testing"

func TestParseIDs(t *testing.T) {
	cases := map[string][]string{
		"":                    nil,
		"  ":                  nil,
		"a":                   {"a"},
		"a,b":                 {"a", "b"},
		" a , b , c ":         {"a", "b", "c"},
		"a,,b, ,c":            {"a", "b", "c"},
	}
	for raw, want := range cases {
		got := parseIDs(raw)
		if len(got) != len(want) {
			t.Fatalf("parseIDs(%q) = %v, want %v", raw, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("parseIDs(%q)[%d] = %q, want %q", raw, i, got[i], want[i])
			}
		}
	}
}
