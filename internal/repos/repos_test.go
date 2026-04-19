package repos

import "testing"

func TestParseRef(t *testing.T) {
	cases := []struct {
		input   string
		wantURL string
		wantRef string
	}{
		// bare URL, no ref
		{"github.com/owner/repo", "github.com/owner/repo", ""},
		// bare URL with tag
		{"github.com/owner/repo@v1.2.3", "github.com/owner/repo", "v1.2.3"},
		// bare URL with branch
		{"github.com/owner/repo@main", "github.com/owner/repo", "main"},
		// https URL, no ref
		{"https://github.com/owner/repo", "https://github.com/owner/repo", ""},
		// https URL with tag
		{"https://github.com/owner/repo@v1.0.0", "https://github.com/owner/repo", "v1.0.0"},
		// git@ SSH URL — never split
		{"git@github.com:owner/repo", "git@github.com:owner/repo", ""},
		// ssh:// URL — never split
		{"ssh://git@github.com/owner/repo", "ssh://git@github.com/owner/repo", ""},
	}

	for _, tc := range cases {
		gotURL, gotRef := ParseRef(tc.input)
		if gotURL != tc.wantURL || gotRef != tc.wantRef {
			t.Errorf("ParseRef(%q) = (%q, %q), want (%q, %q)",
				tc.input, gotURL, gotRef, tc.wantURL, tc.wantRef)
		}
	}
}
