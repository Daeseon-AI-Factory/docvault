package web

import "testing"

func TestCSVSafeFieldPreventsSpreadsheetFormulaInjection(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"equals", "=1+1", "'=1+1"},
		{"plus", "+1+1", "'+1+1"},
		{"minus", "-1+1", "'-1+1"},
		{"at", "@SUM(A1:A2)", "'@SUM(A1:A2)"},
		{"leading tab formula", "\t=1+1", "'\t=1+1"},
		{"normal", `C:\Users\kim\Documents\design.dwg`, `C:\Users\kim\Documents\design.dwg`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := csvSafeField(tt.in); got != tt.want {
				t.Fatalf("csvSafeField(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
