package gomod

import "testing"

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Already has v prefix
		{"v1.2.3", "v1.2.3"},
		{"v0.1.0", "v0.1.0"},
		{"v2.0.0", "v2.0.0"},

		// Missing v prefix (semver)
		{"1.2.3", "v1.2.3"},
		{"0.1.0", "v0.1.0"},
		{"2.0.3", "v2.0.3"},
		{"1.13.3", "v1.13.3"},

		// Special versions
		{"latest", "latest"},
		{"", ""},

		// Edge cases
		{"v1.0.0-alpha", "v1.0.0-alpha"},
		{"1.0.0-beta.1", "v1.0.0-beta.1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeVersion(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeVersion(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsMajorVersionBump(t *testing.T) {
	tests := []struct {
		oldVersion string
		newVersion string
		expected   bool
	}{
		{"v1.2.3", "v1.3.0", false},
		{"v1.2.3", "v2.0.0", true},
		{"v1.2.3", "2.0.3", true},
		{"1.2.5", "2.0.3", true},
		{"v0.1.0", "v1.0.0", true},
		{"v2.0.0", "v2.1.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.oldVersion+"->"+tt.newVersion, func(t *testing.T) {
			result := IsMajorVersionBump(tt.oldVersion, tt.newVersion)
			if result != tt.expected {
				t.Errorf("IsMajorVersionBump(%q, %q) = %v, want %v",
					tt.oldVersion, tt.newVersion, result, tt.expected)
			}
		})
	}
}
