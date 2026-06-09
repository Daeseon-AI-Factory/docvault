package audit

import "testing"

func TestCSVSafePreventsSpreadsheetFormulaInjection(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"equals", "=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0"},
		{"plus", "+SUM(A1:A2)", "'+SUM(A1:A2)"},
		{"minus", "-10+20", "'-10+20"},
		{"at", "@HYPERLINK(\"http://example.test\")", "'@HYPERLINK(\"http://example.test\")"},
		{"leading space formula", " =1+1", "' =1+1"},
		{"normal", "drawing,dwg", "drawing,dwg"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := csvSafe(tt.in); got != tt.want {
				t.Fatalf("csvSafe(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
