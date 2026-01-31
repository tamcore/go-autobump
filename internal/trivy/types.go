package trivy

// ScanResult represents the result of scanning a single go.mod file
type ScanResult struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability represents a single vulnerability found by Trivy
type Vulnerability struct {
	VulnerabilityID  string          `json:"VulnerabilityID"`
	PkgName          string          `json:"PkgName"`
	InstalledVersion string          `json:"InstalledVersion"`
	FixedVersion     string          `json:"FixedVersion"`
	Severity         string          `json:"Severity"`
	Title            string          `json:"Title"`
	Description      string          `json:"Description"`
	PrimaryURL       string          `json:"PrimaryURL"`
	CVSS             map[string]CVSS `json:"CVSS"`
	Indirect         bool            `json:"-"` // Populated from package relationship
	CVSSScore        float64         `json:"-"` // Computed highest CVSS score
}

// CVSS represents CVSS scoring information
type CVSS struct {
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector"`
}

// TrivyOutput represents the full JSON output from Trivy
type TrivyOutput struct {
	Results []TrivyResult `json:"Results"`
}

// TrivyResult represents a single result entry from Trivy
type TrivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"`
	Type            string               `json:"Type"`
	Packages        []TrivyPackage       `json:"Packages"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

// TrivyPackage represents package information from Trivy
type TrivyPackage struct {
	Name         string `json:"Name"`
	Version      string `json:"Version"`
	Relationship string `json:"Relationship"`
	Indirect     bool   `json:"Indirect"`
}

// TrivyVulnerability represents the raw vulnerability from Trivy JSON
type TrivyVulnerability struct {
	VulnerabilityID  string          `json:"VulnerabilityID"`
	PkgName          string          `json:"PkgName"`
	InstalledVersion string          `json:"InstalledVersion"`
	FixedVersion     string          `json:"FixedVersion"`
	Severity         string          `json:"Severity"`
	Title            string          `json:"Title"`
	Description      string          `json:"Description"`
	PrimaryURL       string          `json:"PrimaryURL"`
	CVSS             map[string]CVSS `json:"CVSS"`
}
